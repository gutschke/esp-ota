#include <algorithm>
#include <cstring>
#include <map>
#include <memory>

#include "bootloader_common.h"
#include "bootloader_params.h"
#include "dhcp-options.h"
#include "esp_http_server.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "esp_partition.h"
#include "esp_rom_md5.h"
#include "esp_sleep.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/sockets.h"
#include "nvs_flash.h"
#include "spi_flash_chip_driver.h"
#include "spi_flash_mmap.h"

#pragma GCC diagnostic ignored "-Wmissing-field-initializers"

// Change this function pointer, if you have an app that can display it's on web
// UI.
static esp_err_t (*mainAppHttpHandler)(httpd_req_t* req);

// Notify web socket connections of WiFi scan results.
struct WSState {
  httpd_handle_t hd;
  int fd;
  uint16_t peer;
  bool operator<(const WSState& x) const {
    return hd < x.hd ||
           (hd == x.hd && (fd < x.fd || (fd == x.fd && peer < x.peer)));
  }
};
static std::map<WSState, bool> wsSessions;
static bool wifiScanning{false};

// Wrap millisecond timestamps in a class that helps with doing the correct
// serial number arithmetic when computing timeouts.
class ms_t {
public:
  ms_t() : t(0) {}
  explicit ms_t(uint32_t x) : t(x) {}
  explicit ms_t(const ms_t& x) : t((uint32_t)x) {}
  explicit operator uint32_t() const { return t; }
  constexpr ms_t& operator=(const ms_t& x) = default;

  // https://en.wikipedia.org/wiki/Serial_number_arithmetic
  bool operator<(const ms_t& x) { return (int32_t)(t - (uint32_t)x) < 0; }
  bool operator==(const ms_t& x) { return t == (uint32_t)x; }
  bool operator!() { return !t; }

  // Return the current time in milliseconds as an unsigned quantity.
  // Optionally, add a delta for computing a target time for timeouts. Never
  // returns zero, so that it is easy to distinguish uninitialized values.
  static ms_t now(uint32_t delta = 0) {
    const auto us = esp_timer_get_time();
    uint32_t ms = (uint32_t)((us + 500) / 1000) + delta;
    return ms_t{ms ? ms : ms + 1};
  }

  void reset() { t = 0; }
  bool isExpired() {
    if (!t) return true;
    if (now() < *this) return false;
    t = 0;
    return true;
  }

private:
  uint32_t t;
};
static ms_t now(uint32_t delta = 0) {
  return ms_t::now(delta);
}

// Pass state from the event handler to the network-related tasks.
struct NetworkState {
  esp_netif_t *ap, *sta;
  wifi_ap_config_t apCfg;
  wifi_sta_config_t staCfg;
  httpd_handle_t httpServer;
  enum { DONE, TRYING, STARTING } tryingNewCredentials;
  uint8_t trySSID[32];
  uint8_t tryPSWD[64];
  ms_t blockWiFiReconnectsUntil;
};

// The standard boot loader implements a relatively rigid policy for
// determining the boot partition. We extended it so that we can boot
// into other partitions on demand. Unlike the default OTA mechanism,
// we don't persist this selection. After power-cycling, we would
// follow the default boot order, which prefers the "factory" image
// unless it is damaged. In that case, it executes the "test" image.
static void reboot(uint32_t target = FACTORY_INDEX) {
  auto params{
      (bootloader_params_t*)&bootloader_common_get_rtc_retain_mem()->custom};
  params->partition_index = target;
  esp_deep_sleep(1000 /* 1 ms */);
}

// We create a temporary "test" image when preparing for OTA updates.
// Check whether we are running in that partition or instead in the
// regular "factory" partition.
static bool inTestAppPartition() {
  auto me{spi_flash_cache2phys((void*)inTestAppPartition)};
  auto part{esp_partition_find_first(ESP_PARTITION_TYPE_APP,
                                     ESP_PARTITION_SUBTYPE_APP_FACTORY, NULL)};
  return me < part->address || me >= part->address + part->size;
}

// Switches between the production partition scheme which has a "factory"
// partition followed by a "spiffs" partition, and the OTA mode, that has a
// super-sized "factory" partition and a copy of the previous app in the
// "test" partition. The "spiffs" partition will temporarily be wiped
// during OTA updates. If this function gets called in regular "production"
// mode and there is no request to switch modes, it still checks the
// partition table. If it wastes space, flash memory will be repartioned
// for optimal use. This also wipes the "spiffs" filesystem.
static void switchPartitionMode(bool enableOTAMode) {
  // Stack space is precious. Allocate memory from the heap instead when
  // reading larger amounts of data from flash, such as the 3kB partition
  // table.
  std::unique_ptr<esp_partition_info_t[]> partitions{
      new (std::nothrow) esp_partition_info_t[ESP_PARTITION_TABLE_MAX_ENTRIES]};
  assert(partitions);
  ESP_LOGI(CONFIG_LWIP_LOCAL_HOSTNAME, "Reading partition table from 0x%x",
           CONFIG_PARTITION_TABLE_OFFSET);
  ESP_ERROR_CHECK(esp_flash_read(NULL, partitions.get(),
                                 CONFIG_PARTITION_TABLE_OFFSET,
                                 ESP_PARTITION_TABLE_MAX_LEN));

  // Parse the current partition table. In order for our code to work as
  // intended, the last two partitions must be a "factory" partition followed
  // by the main "data" partition (e.g. a SPIFFS image) or alternatively
  // a "test" partition while in OTA mode.
  int8_t appIdx{-1}, dataOrTestIdx{-1};
  bool inOTAMode{false};
  for (auto i = 0; i < ESP_PARTITION_TABLE_MAX_ENTRIES; ++i) {
    const auto& entry{partitions[i]};
    if (entry.magic == ESP_PARTITION_MAGIC) {
#if CONFIG_LOG_DEFAULT_LEVEL != LOG_LEVEL_NONE
      // Print the current partion table for debugging purposes.
      char label[sizeof(entry.label) + 1];

      memcpy(label, entry.label, sizeof(entry.label));
      label[sizeof(entry.label)] = '\000';
      ESP_LOGI("esp_ota", "%s, %s, %d, 0x%lx, 0x%lx, %s", label,
               entry.type == ESP_PARTITION_TYPE_APP ? "app" : "data",
               entry.subtype, entry.pos.offset, entry.pos.size,
               (entry.flags & 1) ? "encrypted" : "");
#endif
      // Identify our two different target partitions.
      if (entry.type == ESP_PARTITION_TYPE_APP &&
          entry.subtype == ESP_PARTITION_SUBTYPE_APP_FACTORY) {
        assert(appIdx == -1);
        assert(dataOrTestIdx == -1);
        const auto me{spi_flash_cache2phys((void*)switchPartitionMode)};
        inOTAMode = me >= entry.pos.offset + entry.pos.size;
        appIdx = i;
      } else if ((entry.type == ESP_PARTITION_TYPE_APP &&
                  entry.subtype == ESP_PARTITION_SUBTYPE_APP_TEST) ||
                 (entry.type == ESP_PARTITION_TYPE_DATA &&
                  entry.subtype == ESP_PARTITION_SUBTYPE_DATA_SPIFFS)) {
        assert(appIdx >= 0);
        assert(dataOrTestIdx == -1);
        dataOrTestIdx = i;
      }
#if CONFIG_LOG_DEFAULT_LEVEL != LOG_LEVEL_NONE
    } else if (entry.magic == ESP_PARTITION_MAGIC_MD5) {
      // Check the MD5 signature, if present. This code can safely be
      // removed though. There shouldn't be any scenario allowing us to
      // boot into our application with an incorrect signature.
      assert(dataOrTestIdx == i - 1);
      const auto digest{(uint8_t*)&entry + 16};
      char buf[50];
      for (int i = 0; i < 16; ++i)
        sprintf(&buf[3 * i], "%02X ", digest[i]);
      ESP_LOGI(CONFIG_LWIP_LOCAL_HOSTNAME, "MD5 digest: %s", buf);
      MD5Context md5ctx;
      esp_rom_md5_init(&md5ctx);
      esp_rom_md5_update(&md5ctx, (uint8_t*)partitions.get(),
                         i * sizeof(entry));
      esp_rom_md5_final((uint8_t*)&buf[sizeof(buf) - 16], &md5ctx);
      if (memcmp((uint8_t*)&buf[sizeof(buf) - 16], digest, 16)) {
        for (int i = 0; i < 16; ++i)
          sprintf(&buf[3 * i], "%02X ", buf[sizeof(buf) - 16 + i]);
        ESP_LOGI(CONFIG_LWIP_LOCAL_HOSTNAME, "Should be:  %s", buf);
      }
      // Technically, there should be an end-of-table marker after the
      // MD5 signature. We don't enforce this, other than having an assertion
      // that can be compiled-out.
      assert(i < ESP_PARTITION_TABLE_MAX_ENTRIES - 1 &&
             partitions[i + 1].magic == 0xFFFF);
#endif
      break;
    } else if (entry.magic == 0xFFFF) {
#if CONFIG_LOG_DEFAULT_LEVEL != LOG_LEVEL_NONE
      // The partition table ends, when we find the 0xFFFF end-of-table marker.
      // MD5 signatures can be disabled in the configuration. So, skip the
      // check, if they aren't present.
      ESP_LOGI(CONFIG_LWIP_LOCAL_HOSTNAME,
               "End of partition table, but no MD5 checksum found");
#endif
      assert(dataOrTestIdx == i - 1);
      break;
    } else {
      ESP_LOGI(CONFIG_LWIP_LOCAL_HOSTNAME, "Corrupted partition table entry");
      abort();
    }
  }
  assert(appIdx >= 0 && dataOrTestIdx == appIdx + 1);

  // Parse the application's image file and compute the space required to store
  // it. This requires iterating over the flash information and finding all
  // headers for the various segments mapped into memory.
  esp_image_header_t app;
  auto appOffset{partitions[appIdx].pos.offset};
  ESP_ERROR_CHECK(esp_flash_read(NULL, &app, appOffset, sizeof(app)));
  if (app.magic != ESP_IMAGE_HEADER_MAGIC) {
    ESP_LOGI(CONFIG_LWIP_LOCAL_HOSTNAME, "Application image header is corrupt");
  } else {
    // The image size is the total of the image header, all combined segment
    // headers, and the data in each segment.
    auto offset{sizeof(app)};
    for (int i = 0; i < app.segment_count; ++i) {
      esp_image_segment_header_t segment;
      ESP_ERROR_CHECK(
          esp_flash_read(NULL, &segment, offset + appOffset, sizeof(segment)));
      offset += sizeof(segment) + segment.data_len;
    }
    // Image sized must be aligned to 16 bytes because of prefetch caches that
    // can read up to 16 bytes past the end of a binary image.
    offset = (offset + 0xF) & ~0xF;
    // There is an optional SHA256 hash at the end of the entire image.
    if (app.hash_appended) offset += 32;
    // Print the information that we have retrieved for our application image.
    ESP_LOGI(CONFIG_LWIP_LOCAL_HOSTNAME, "Total image size: %d (0x%x)", offset,
             offset);
    // The optimal size for our partition is the size of the image rounded up
    // to 64kB.
    auto appSz{(offset + 0xFFFF) & ~0xFFFF};
    // In production mode, the optimal application size is the same as the
    // properly padded size of the image. In OTA mode, the application
    // should take up as much space as possible, leaving just enough room at
    // the top of the flash for the "test" partition.
    uint32_t flashSz;
    ESP_ERROR_CHECK(esp_flash_get_physical_size(NULL, &flashSz));
    auto optimalSz{enableOTAMode ? flashSz - appOffset - appSz : appSz};
    // The data partition takes up the remainder of the flash memory.
    auto dataOrTestSz{flashSz - optimalSz - appOffset};
    // ESP32-IDF tries oh so hard to prevent us from overwriting the
    // partition table. What a valiant effort, but its struggles as all things
    // are ultimately doomed to failure. It is no match for our grit,
    // determination, and sheer brute force. If nothing else works, we
    // simply define our own flash chip.
    auto rw{*esp_flash_default_chip};
    auto os_func{*rw.os_func};
    os_func.region_protected = [](void*, size_t, size_t) { return ESP_OK; };
    rw.os_func = &os_func;
    const auto sectorSz{esp_flash_default_chip->chip_drv->sector_size};
    // If we want to perform an OTA update momentarily, we have to make sure we
    // execute code from somewhere other than where we are going to write.
    // Temporarily, relocate ourselves to the data partition, overwritting
    // whatever might reside there.
    if (enableOTAMode && !inOTAMode) {
      ESP_LOGI(CONFIG_LWIP_LOCAL_HOSTNAME,
               "Relocate ourselves into the test partition");
      ESP_ERROR_CHECK(esp_flash_erase_region(&rw, appOffset + appSz,
                                             flashSz - appOffset - appSz));
      std::unique_ptr<char[]> sector{new (std::nothrow) char[sectorSz]};
      assert(sector);
      for (size_t offset = 0; offset < appSz; offset += sectorSz) {
        ESP_ERROR_CHECK(
            esp_flash_read(NULL, sector.get(), appOffset + offset, sectorSz));
        ESP_ERROR_CHECK(esp_flash_write(
            &rw, sector.get(), flashSz - dataOrTestSz + offset, sectorSz));
      }
    }

    // This is where the magic happens. We adjust our application partition to
    // its optimal size, and tweak the properties of the data partition
    // accordingly.
    if (partitions[appIdx].pos.size != optimalSz ||
        partitions[dataOrTestIdx].pos.size != dataOrTestSz ||
        partitions[dataOrTestIdx].type !=
            (enableOTAMode ? PART_TYPE_APP : PART_TYPE_DATA)) {
      if (!inOTAMode && partitions[dataOrTestIdx].type == PART_TYPE_APP) {
        ESP_LOGI(CONFIG_LWIP_LOCAL_HOSTNAME,
                 "Erasing old temporary copy of application");
        ESP_ERROR_CHECK(
            esp_flash_erase_region(&rw, partitions[dataOrTestIdx].pos.offset,
                                   partitions[dataOrTestIdx].pos.size));
      }
      partitions[dataOrTestIdx].type =
          enableOTAMode ? PART_TYPE_APP : PART_TYPE_DATA;
      partitions[dataOrTestIdx].subtype =
          enableOTAMode ? PART_SUBTYPE_TEST : ESP_PARTITION_SUBTYPE_DATA_SPIFFS;
      partitions[appIdx].pos.size = optimalSz;
      partitions[dataOrTestIdx].pos.offset = appOffset + optimalSz;
      partitions[dataOrTestIdx].pos.size = dataOrTestSz;
      // Of course, any time the partition table changes, we have to recompute
      // the MD5 checksum, if present.
      MD5Context md5ctx;
      esp_rom_md5_init(&md5ctx);
      for (auto i = 0; i < ESP_PARTITION_TABLE_MAX_ENTRIES; ++i) {
        const esp_partition_info_t& entry = partitions[i];
        if (entry.magic == ESP_PARTITION_MAGIC_MD5) {
          esp_rom_md5_update(&md5ctx, (uint8_t*)partitions.get(),
                             i * sizeof(entry));
          esp_rom_md5_final((uint8_t*)&entry + 16, &md5ctx);
          break;
        } else if (entry.magic == 0xFFFF && entry.type == 0xFF &&
                   entry.subtype == 0xFF) {
          break;
        }
      }
      // Flash memory is not like other types of storage. We have to erase it
      // first before we can overwrite it. Remember that it can only be erased
      // in multiples of the sector size (usually 4kB).
      ESP_LOGI(CONFIG_LWIP_LOCAL_HOSTNAME, "Flashing new partition table");
      ESP_ERROR_CHECK(
          esp_flash_erase_region(&rw, CONFIG_PARTITION_TABLE_OFFSET,
                                 (ESP_PARTITION_TABLE_MAX_LEN + sectorSz - 1) &
                                     ~(rw.chip_drv->sector_size - 1)));
      ESP_ERROR_CHECK(esp_flash_write(&rw, partitions.get(),
                                      CONFIG_PARTITION_TABLE_OFFSET,
                                      ESP_PARTITION_TABLE_MAX_LEN));
      ESP_LOGI(
          CONFIG_LWIP_LOCAL_HOSTNAME, "%s",
          enableOTAMode
              ? "Adjusted partition table, copied app, now rebooting for OTA"
              : "Adjusted partition table, rebooting now for the changes to "
                "take effect");
      reboot(enableOTAMode ? TEST_APP_INDEX : FACTORY_INDEX);
    } else if (enableOTAMode) {
      ESP_LOGI(CONFIG_LWIP_LOCAL_HOSTNAME,
               "The partition table looks fine, but rebooting for OTA");
      reboot(TEST_APP_INDEX);
    }
  }
  ESP_LOGI(CONFIG_LWIP_LOCAL_HOSTNAME,
           "Everything looks good, nothing to do right now...");
  return;
}

// Identify the peer on the other end of a socket. This is helpful when keeping
// track of web sockets, as the combination of handle and fd often gets re-used.
// This shouldn't be an issue as we carefully track the life-cycle of WebSockets
// by monitoring control messages; but better add the peer as another
// disambiguation.
static uint16_t peerPort(int fd) {
  struct sockaddr_in6 in;
  socklen_t len{sizeof(in)};
  return getpeername(fd, (sockaddr*)&in, &len) ? -1 : ntohs(in.sin6_port);
}

// We start WiFi scanning a little while after we have been asked to do so. That
// gives the network stack time to quiet down and decreases the chances of us
// losing network packets while actively scanning.
static void wifiScannerJob(void*) {
  wifi_scan_config_t cfg{.show_hidden{true},
                         .scan_type{WIFI_SCAN_TYPE_ACTIVE},
                         .scan_time{.active{.max{150}}},
                         .home_chan_dwell_time{250}};
  // We can only scan, if STA is enabled. Turn it on temporarily.
  wifi_mode_t mode;
  esp_wifi_get_mode(&mode);
  if (mode == WIFI_MODE_AP) esp_wifi_set_mode(WIFI_MODE_APSTA);
  esp_wifi_scan_start(&cfg, false);
  return;
}

// There was a change to the active WebSocket sessions or there we have received
// all WiFi scan results. Either option might require us to start/stop scanning
// for WiFi access points.
static void wifiScanner() {
  bool hasListeners{false};
  // If at least one WebSocket session has responded to our previous scan
  // results and is now waiting for more, we can resume scanning.
  for (auto it = wsSessions.begin(); it != wsSessions.end(); ++it)
    if (it->second) {
      hasListeners = true;
      break;
    }
  // Check whether anything has changed from when we were called last.
  if (wifiScanning != hasListeners) {
    wifiScanning = hasListeners;
    static esp_timer_handle_t timer{};
    if (wifiScanning) {
      // Create a timer to invoke WiFi scanning with a short delay.
      if (!timer) {
        esp_timer_create_args_t args{.callback{wifiScannerJob},
                                     .dispatch_method{ESP_TIMER_TASK},
                                     .name{"wifi-scan"}};

        ESP_ERROR_CHECK(esp_timer_create(&args, &timer));
      }
      // If we weren't scanning yet, (re)start the timer.
      esp_timer_start_once(timer, 100 * 1000);
    } else {
      // Stop the timer, if it hasn't gone off yet. Then stop the scan.
      if (timer) esp_timer_stop(timer);
      esp_wifi_scan_stop();
    }
  }
  return;
}

// When the WiFi scan is completed, reap the results, broadcast to listeners,
// and see if we need to restart scanning.
class SSIDs {
public:
  esp_err_t addToCache(const uint8_t (&ssid)[MAX_SSID_LEN + 1],
                       uint8_t channel,
                       int8_t rssi,
                       bool open) {
    // Common usage scenarios for these device would have lots of them in the
    // same location. None are connected to the internet through their SoftAP.
    // So, filter those out during scanning.
    if (open && ssid[sizeof(CONFIG_LWIP_LOCAL_HOSTNAME) - 1] == '-' &&
        !memcmp(ssid, CONFIG_LWIP_LOCAL_HOSTNAME,
                sizeof(CONFIG_LWIP_LOCAL_HOSTNAME) - 1))
      return ESP_OK;
#ifdef __EXCEPTIONS
    try {
#endif
      auto it = cache_.find(std::to_array(ssid));
      if (it == cache_.end())
        cache_[std::to_array(ssid)] =
            CacheEntry{generation_, channel, rssi, open};
      else {
        if (it->second.generation != generation_ || it->second.rssi < rssi) {
          it->second.generation = generation_;
          it->second.channel = channel;
          it->second.rssi = rssi;
          it->second.open = open;
        }
      }
#ifdef __EXCEPTIONS
    } catch (const std::bad_alloc&) {
      cache_.clear();
      return ESP_ERR_NO_MEM;
    }
#endif
    return ESP_OK;
  }

  void* assembleWSPacket(bool nextGeneration) {
    auto dataLen{spaceNeeded()};
    if (!dataLen) return NULL;
    auto state = (SSIDState*)calloc(1, sizeof(SSIDState) + dataLen);
    if (!state) return NULL;
    if (nextGeneration) ++generation_;

    auto& wsPacket{state->wsPacket};
    wsPacket.type = HTTPD_WS_TYPE_TEXT;
    wsPacket.len = dataLen;
    wsPacket.payload = (uint8_t*)&state[1];
    state->outstanding = 1;
    char* ptr{state->payload};

    // Assemble payload of WebSocket message.
    for (auto it = cache_.begin(); it != cache_.end(); ++it) {
      if (it->second.open /* Open WiFi network*/) *ptr++ = '\1';
      ptr += 1 + strlen(strcpy(ptr, (char*)it->first.data()));
    }

    return state;
  }

  static void sendWSMessage(void* arg, decltype(wsSessions)::iterator sess) {
    if (!arg) return;
    auto state{(SSIDState*)arg};
    // Mark WebSocket as responded. We won't initiate another
    // scan until the HTML client tells us to. This slows things
    // down, but it helps with reliability when changing radio
    // frequencies during a WiFi scan.
    sess->second = false;
    state->outstanding++;
    auto rc = httpd_ws_send_data_async(sess->first.hd, sess->first.fd,
                                       &state->wsPacket, cleanupState, arg);
    if (rc != ESP_OK) cleanupState(rc, sess->first.fd, arg);
  }

  static void cleanup(void* arg) { cleanupState(ESP_OK, -1, arg); }

  uint8_t preferredChannel(const uint8_t* ssid) {
    std::array<uint8_t, MAX_SSID_LEN + 1> key;
    auto ptr = memchr(ssid, 0, MAX_SSID_LEN);
    auto len = ptr ? (uint8_t*)ptr - ssid : MAX_SSID_LEN;
    memcpy(key.data(), ssid, len);
    memset(key.data() + len, 0, MAX_SSID_LEN + 1 - len);
    auto it = cache_.find(key);
    if (it == cache_.end()) return 0;
    return it->second.channel;
  }

private:
  size_t spaceNeeded() {
    size_t dataLen{};
    for (auto it = cache_.begin(); it != cache_.end();) {
      // We do eventually remove stale WiFi access points when they
      // no longer show up in scans. But since scans are notoriously
      // unreliable, we err on the side of caching old data for
      // quite a while.
      if ((int8_t)(generation_ - it->second.generation) > 30)
        it = cache_.erase(it);
      else {
        if (it->second.open /* Open WiFi network*/) dataLen++;
        dataLen += 1 + strlen((char*)it++->first.data());
      }
    }
    return dataLen;
  }

  // Clean up our state once the last outstanding asynchronous messages
  // has been sent. We initialize "state->outstanding" to one, in order to
  // avoid possible race conditions.
  static void cleanupState(esp_err_t err, int fd, void* arg) {
    auto state{(SSIDState*)arg};
    if (err != ESP_OK) {
      auto peer{peerPort(fd)};
      // We currently only have a single HTTPD server instance, but in the
      // interest of generality, scan the active WebSocket sessions to find
      // the server that is associated with a given file descriptor.
      for (auto it = wsSessions.begin(); it != wsSessions.end(); ++it) {
        if (it->first.fd == fd && it->first.peer == peer) {
          // Error sending message on WebSocket. Close it now.
          httpd_handle_t hd{it->first.hd};
          wsSessions.erase(it);
          httpd_sess_trigger_close(hd, fd);
          break;
        }
      }
    }
    // Clean up our dynamically allocated state.
    if (arg && !--state->outstanding) free(arg);
    return;
  }

  // Scan results go into a case-insensitive cache that slowly expires old
  // records over time. This neatly deals with access points that only
  // respond occasionally to our scans.
  struct CacheEntry {
    CacheEntry(uint8_t generation = 0,
               uint8_t channel = 0,
               int8_t rssi = 0,
               bool open = false)
        : generation(generation), channel(channel), rssi(rssi), open(open) {}
    uint8_t generation;
    uint8_t channel;
    int8_t rssi;
    bool open;
    bool operator()(std::array<uint8_t, MAX_SSID_LEN + 1> lhs,
                    std::array<uint8_t, MAX_SSID_LEN + 1> rhs) const {
      return strcasecmp((char*)lhs.data(), (char*)rhs.data()) < 0;
    }
  };
  std::map<std::array<uint8_t, MAX_SSID_LEN + 1>, CacheEntry, CacheEntry>
      cache_;

  // Since are sending data asynchronously to all the listening WebSockets,
  // we have to dynamically allocate memory to keep track of our state. This
  // includes but is not limited to the payload that we are sending over the
  // WebSocket(s). And of course, we don't know the size of the payload
  // until we have iterated over the scan results, so allocation is delayed
  // until then.
  struct SSIDState {
    httpd_ws_frame_t wsPacket;
    int outstanding;
    char payload[];
  };

  // Increment a generation counter on each completed WiFi scan.
  uint8_t generation_{};
};
static SSIDs ssids;

static void wifiScanDone(void*) {
  uint16_t num;
  wifi_ap_record_t* records{};
  if (esp_wifi_scan_get_ap_num(&num) == ESP_OK) {
    // We have to allocate enough space to hold all search results. But
    // even if the allocation fails, we must call
    // esp_wifi_scan_get_ap_records() to clean up resources. Error
    // handling is tricky here. Setting the number of records to zero, if we
    // fail to allocate a buffer ensures that we still clean up afterwards.
    if (!(records = (wifi_ap_record_t*)malloc(num * sizeof(*records)))) num = 0;
    if (esp_wifi_scan_get_ap_records(&num, records) == ESP_OK && num) {
      for (int i = 0; i < num; ++i)
        if (*records[i].ssid)
          ssids.addToCache(records[i].ssid, records[i].primary, records[i].rssi,
                           records[i].authmode == WIFI_AUTH_OPEN);
      auto state{ssids.assembleWSPacket(true)};
      if (state) {
        // Sending a message on a web socket can trigger events that
        // end up marking the session as closed. This can cause us to
        // modify the "wsSessions" map concurrently with iterating
        // over it. Create a copy of the map first and then verify
        // that the global map still contains our session before
        // operating on it.
#ifdef __EXCEPTIONS
        try {
#endif
          auto cpy{wsSessions};
          for (auto it = cpy.begin(); it != cpy.end(); ++it) {
            decltype(wsSessions)::iterator sess;
            // Only send a message, if the WebSocket hasn't previously been
            // closed, and only if it has acknowledged our previous message.
            if (it->second && peerPort(it->first.fd) == it->first.peer &&
                (sess = wsSessions.find(it->first)) != wsSessions.end()) {
              ssids.sendWSMessage(state, sess);
            }
#ifdef __EXCEPTIONS
          }
          catch (const std::bad_alloc&) {
          }
#endif
        }
      }
      // If we never sent any messages, we now clean up our dynamically
      // allocated state. Otherwise, that will happen when the last message
      // has finished sending.
      ssids.cleanup(state);
    }
  }
  free(records);
  wifiScanning = false;
  wifiScanner();
  return;
}

// Checks whether the client connected to our AP which is used for the
// configuration GUI, or whether our HTTP server is operating in STA mode. In
// that case, we don't expose the configuration interface.
static bool clientConnectedToAP(httpd_req_t* req) {
  auto fd{httpd_req_to_sockfd(req)};
  sockaddr_in6 in;
  socklen_t inLen{sizeof(in)};
  if (!getsockname(fd, (sockaddr*)&in, &inLen)) {
    auto ap{((NetworkState*)req->user_ctx)->ap};
    esp_netif_ip_info_t info;
    esp_netif_get_ip_info(ap, &info);
    return !memcmp(&info.ip.addr, &in.sin6_addr.un.u32_addr[3],
                   sizeof(info.ip.addr));
  }
  return true;
}

// Redirect all unexpected requests to our main page. This is part of the
// captive portal configuration.
static esp_err_t redirectHandler(httpd_req_t* req, const char* path = "") {
  httpd_resp_set_type(req, "text/html");
  httpd_resp_set_status(req, "301 Moved Permanently");
  auto fd{httpd_req_to_sockfd(req)};
  sockaddr_in6 in;
  socklen_t len{sizeof(in)};
  if (!getsockname(fd, (sockaddr*)&in, &len)) {
    char buf[40 + sizeof(CONFIG_LWIP_LOCAL_HOSTNAME)];
    snprintf(buf, sizeof(buf), "http://%s/%s",
             inet_ntop(AF_INET, &in.sin6_addr.un.u32_addr[3],
                       &buf[sizeof(buf) - 16], 16),
             path);
    httpd_resp_set_hdr(req, "Location", buf);
    ESP_LOGI(CONFIG_LWIP_LOCAL_HOSTNAME, "Redirecting to \"%s\"", buf);
  }
  return httpd_resp_send(req, NULL, 0);
}

// We asked the web socket subsystem to send us control messages. That means,
// we are now responsible to actually respond to them.
static esp_err_t maybeHandleWSCtrl(httpd_req_t* req,
                                   httpd_ws_type_t* type = NULL,
                                   char** buf = NULL,
                                   size_t* len = NULL) {
  // Check if this is even web socket connection in the first place. The
  // caller shouldn't have called us otherwise.
  if (buf) *buf = NULL;
  if (len) *len = 0;
  if (type) *type = (httpd_ws_type_t)-1;
  if (req->method) {
    return ESP_ERR_INVALID_STATE;
  }
  // Prepare to load the web socket payload;
  httpd_ws_frame_t wsPacket{.type{HTTPD_WS_TYPE_TEXT}};
  auto rc{httpd_ws_recv_frame(req, &wsPacket, 0)};
  if (rc < 0) return rc;

  // Knowing the payload length, we can try to retrieve the data.
  if (wsPacket.len > 0) {
    wsPacket.payload = (uint8_t*)malloc(wsPacket.len + 1);
    if (!wsPacket.payload) return ESP_ERR_NO_MEM;

    rc = httpd_ws_recv_frame(req, &wsPacket, wsPacket.len);
    if (rc < 0) goto done;

    wsPacket.payload[wsPacket.len] = '\0';
  }
  if (type) *type = wsPacket.type;
  switch (wsPacket.type) {
    case HTTPD_WS_TYPE_PING:
      wsPacket.type = HTTPD_WS_TYPE_PONG;
      goto respond;
    case HTTPD_WS_TYPE_CLOSE:
      free(wsPacket.payload);
      wsPacket.payload = NULL;
      wsPacket.len = 0;
    respond:
      rc = httpd_ws_send_frame(req, &wsPacket);
      break;
    case HTTPD_WS_TYPE_BINARY:
    case HTTPD_WS_TYPE_TEXT:
      break;
    default:
      ESP_LOGI(CONFIG_LWIP_LOCAL_HOSTNAME,
               "Unexpected WebSocket control message %d", wsPacket.type);
      break;
  }
  if (buf && len) {
    *buf = (char*)wsPacket.payload;
    *len = wsPacket.len;
    return rc;
  }
done:
  free(wsPacket.payload);
  return rc;
}

// The user entered new WiFi credentials. Attempt to connect to them in STA
// mode.
static wifi_mode_t preferredWiFiMode(NetworkState*, bool);
static void connectToWifi(NetworkState* state,
                          const char* ssid,
                          const char* pswd) {
  ESP_LOGI(CONFIG_LWIP_LOCAL_HOSTNAME, "connectToWifi(\"%s\", \"%s\")", ssid,
           pswd);
  // wifi_sta_config_t has both an ssid and a password field. These
  // fields are zero padded up to a maximum length of 32 or 64 bytes
  // respectively. That means, they are not necessarily zero
  // terminated.
  state->tryingNewCredentials = NetworkState::STARTING;
  memset(state->trySSID, 0, sizeof(state->trySSID));
  memset(state->tryPSWD, 0, sizeof(state->tryPSWD));
  memcpy(state->trySSID, ssid, std::min(sizeof(state->trySSID), strlen(ssid)));
  memcpy(state->tryPSWD, pswd, std::min(sizeof(state->tryPSWD), strlen(pswd)));
  preferredWiFiMode(state, true);
  // Disconnecting from WiFi disrupts active WiFi connections. Delay until we
  // have returned from current HTTP request.
  httpd_queue_work(
      state->httpServer,
      [](void*) {
        uint16_t aid;
        if (esp_wifi_sta_get_aid(&aid) == ESP_OK && aid)
          esp_wifi_disconnect();
        else
          esp_wifi_connect();
      },
      NULL);
  return;
}

// The web server for the configuration GUI supports both GET requests for
// static embedded files and web socket requests for configuration management.
static esp_err_t cfgHttpHandler(httpd_req_t* req) {
  if (req->method == HTTP_GET) {
    // If this is an HTTP connection in the process of being upgraded to a web
    // socket connection, we shouldn't try to return any data for the request.
    // It's just going to mess up the web socket.
    auto rc{
        httpd_req_get_hdr_value_str(req, "Sec-WebSocket-Protocol", NULL, 0)};
    if (rc == ESP_OK || rc == ESP_ERR_HTTPD_RESULT_TRUNC) {
#ifdef __EXCEPTIONS
      try {
#endif
        auto fd{httpd_req_to_sockfd(req)};
        auto ins{wsSessions.insert(
            std::make_pair(WSState{req->handle, fd, peerPort(fd)}, true))};
        // If we already have a cached list of access points, we can reply
        // immediately. If not, we'll initiate a fresh scan.
        auto state{ssids.assembleWSPacket(false)};
        ssids.sendWSMessage(state, ins.first);
        ssids.cleanup(state);
#ifdef __EXCEPTIONS
      } catch (const std::bad_alloc&) {
        wsSessions.clear();
      }
#endif
      wifiScanner();
      return ESP_OK;
    }
    extern const char index_start[] asm("_binary_idx_start");
    extern const char index_end[] asm("_binary_idx_end");
    static const struct {
      const char *path, *mimeType, *data;
      const size_t len;
    } files[]{
        // Add more embedded static files here. Try to minimize the number of
        // active HTTP requests though. Our network stack and the HTTP server
        // have very small resource limits. This means, instead of referencing
        // other resources from within HTML files, it is more efficient to try
        // to bundle them all inside the same file.
        {"/", "text/html", index_start, (size_t)(index_end - index_start)},
    };
    for (int i = sizeof(files) / sizeof(*files); i--;) {
      if (!strcmp(req->uri, files[i].path)) {
        httpd_resp_set_type(req, files[i].mimeType);
        return httpd_resp_send(req, files[i].data, files[i].len);
      }
    }
    return redirectHandler(req);
  }
  // If we get here, we must be working with a web socket. Determine the
  // payload length.
  httpd_ws_type_t type;
  char* buf;
  size_t len;
  auto rc{maybeHandleWSCtrl(req, &type, &buf, &len)};
  if (rc != ESP_OK) {
    int fd = httpd_req_to_sockfd(req);
    wsSessions.erase(WSState{req->handle, fd, peerPort(fd)});
    httpd_sess_trigger_close(req->handle, fd);
  }
  int fd{httpd_req_to_sockfd(req)};
  switch (type) {
    case HTTPD_WS_TYPE_CLOSE:
      wsSessions.erase(WSState{req->handle, fd, peerPort(fd)});
      wifiScanner();
      break;
    case HTTPD_WS_TYPE_TEXT:
    case HTTPD_WS_TYPE_BINARY:
      if (len) {
        if (*buf == ' ') {
          // Received an acknowledgement from the web client. We can resume
          // scanning.
          for (auto it = wsSessions.begin(); it != wsSessions.end(); ++it)
            if (it->first.hd == req->handle && it->first.fd == fd) {
              it->second = true;
              break;
            }
          wifiScanner();
        } else if (*buf == '\0' && len >= 4) {
          const auto ssid = buf + 1;
          auto pswd = (char*)memchr(ssid, 0, len - (ssid - buf));
          auto state{(NetworkState*)req->user_ctx};
          if (pswd++ && memchr(pswd, 0, len - (pswd - buf)) &&
              pswd - ssid - 1 <= sizeof(state->staCfg.ssid) &&
              strlen(pswd) <= sizeof(state->staCfg.password)) {
            connectToWifi(state, ssid, pswd);
          }
        }
      }
      break;
    default:
      break;
  }
  free(buf);
  return rc;
}

// Return static files in response to HTTP requests or handle web socket
// requests. Also, implement reasonable heuristics for whether we should
// show the initial configuration GUI (e.g. for setting the site-specific WiFi
// credentials) or whether to show the main application.
static esp_err_t httpHandler(httpd_req_t* req) {
  // By default, when accessing the root of the web server, the configuration
  // GUI is exposed on the SoftAP, whereas the main application is accessible
  // when the device connected in STA mode.
  // Upon a user's request, the application can also be started from the
  // configuration GUI and will then become accessible at the root URI until
  // power-cycled. The special URIs "/${APP}-cfg" and "/${APP}-app" are
  // always available to by-pass this automated mechanism.
  bool forceApp{false}, forceCfg{false};
  const auto uri{req->uri};
  if (*uri == '/' && !memcmp(uri + 1, CONFIG_LWIP_LOCAL_HOSTNAME,
                             sizeof(CONFIG_LWIP_LOCAL_HOSTNAME))) {
    auto removeCount{sizeof(CONFIG_LWIP_LOCAL_HOSTNAME) - 1};
    if (!memcmp(&uri[sizeof(CONFIG_LWIP_LOCAL_HOSTNAME) + 1], "-app", 4)) {
      removeCount += sizeof("-app") - 1;
      forceApp = true;
      goto removeURIPath;
    } else if (!memcmp(&uri[sizeof(CONFIG_LWIP_LOCAL_HOSTNAME) + 1], "-cfg",
                       4)) {
      removeCount += sizeof("-cfg") - 1;
      forceCfg = true;
    removeURIPath:
      memmove((char*)&uri[1], &uri[removeCount + 1],
              strlen(&uri[removeCount + 1]) + 1);
    }
  }
  bool onSoftAP{clientConnectedToAP(req)};
  // If accessing through the SoftAP (which defaults to showing the
  // configuration GUI upon power on), permanently switch to the main
  // application the first time it gets access. This can be reset by power
  // cycling. Or of course, the user can always explicitly decide to go to
  // "${APP}-app".
  static bool appEnabled{false};
  appEnabled |= onSoftAP && forceApp;
  // There are several conditions that make us display the main app, and a
  // few that make us display the configuration GUI. Of course, all of this is
  // moot, if there isn't even a main app registered.
  if ((appEnabled || !onSoftAP || forceApp) && !forceCfg &&
      mainAppHttpHandler) {
    // We asked the web socket subsystem to send us control messages. This
    // means we are responsible for implementing them. The main application
    // might not know how to do so, though.
    return mainAppHttpHandler(req);
  }
  return cfgHttpHandler(req);
}

// Immediately reset all requests arriving on port 443. That's good enough to
// make browsers give up on automatically upgrading captive portals to HTTPS.
static void reset443(void* arg) {
  auto state{(NetworkState*)arg};
  for (int sock;;) {
    while (!state->ap) {
      vTaskDelay(pdMS_TO_TICKS(1000));
    }
    for (;;) {
      // Try opening the socket until it succeeds.
      sock = socket(AF_INET, SOCK_STREAM, 0);
      if (sock >= 0) break;
      vTaskDelay(pdMS_TO_TICKS(1000));
    }
    // Only listen on the IP address of the SoftAP. It shouldn't ever
    // change at run-time, but just to be on the safe side, we reload the
    // IP address every time. For now, we only support IPv4, though.
    esp_netif_ip_info_t info;
    esp_netif_get_ip_info(state->ap, &info);
    sockaddr_in httpsAddr{
        .sin_len{sizeof(httpsAddr)},
        .sin_family{AF_INET},
        .sin_port{htons(443)},
        .sin_addr{info.ip.addr},
    };
    // If we can't listen on the interface, try again later. Maybe, the SoftAP
    // is (re)intializing.
    if (bind(sock, (sockaddr*)&httpsAddr, sizeof(httpsAddr)) < 0) {
    err:
      close(sock);
      vTaskDelay(pdMS_TO_TICKS(1000));
      continue;
    }
    for (int fd;;) {
      if (listen(sock, 5) || (fd = accept(sock, 0, 0)) < 0) goto err;
      close(fd);
    }
  }
}

// Initialize the webserver. This creates both a regular web server for
// unencrypted HTTP and another one for HTTPS. The HTTPS server isn't really
// good for much, as it immediately resets the connection after accepting it.
// That's just enough to make captive portals work, when browsers implement
// opportunistic HTTPS-upgrade. We could of course implement SSL, but that
// takes up a lot of space in flash, and as a local device that doesn't have
// any way of getting a valid SSL certificate, we'd only be using self-signed
// certificates anyway. That doesn't help much, and it really doesn't help
// with captive portals.
static httpd_handle_t initHTTPD(NetworkState* state) {
  const auto matchAll{[](const char*, const char*, size_t) { return true; }};
  httpd_config_t cfg = HTTPD_DEFAULT_CONFIG();
  cfg.uri_match_fn = matchAll;
  cfg.enable_so_linger = true;
  cfg.close_fn = [](httpd_handle_t hd, int fd) {
    wsSessions.erase(WSState{hd, fd, peerPort(fd)});
    close(fd);
    wifiScanner();
  };
  httpd_handle_t httpServer{};
  if (!httpd_start(&httpServer, &cfg)) {
    httpd_uri_t handler{.uri{""},
                        .method{HTTP_GET},
                        .handler{httpHandler},
                        .user_ctx{state},
                        .is_websocket{true},
                        .handle_ws_control_frames{true},
                        .supported_subprotocol{"cfg"}};
    httpd_register_uri_handler(httpServer, &handler);
  }
  const auto alwaysRedirect = [](httpd_req* req, httpd_err_code_t err) {
    return redirectHandler(req);
  };
  for (auto err = httpd_err_code_t{}; err < HTTPD_ERR_CODE_MAX;
       err = (httpd_err_code_t)((int)err + 1)) {
    httpd_register_err_handler(httpServer, err, alwaysRedirect);
  }
  xTaskCreate(reset443, "fakehttps", 2048, &state, configMAX_PRIORITIES - 1, 0);
  return httpServer;
}

// Advertise our own IP address as a captive portal in the DHCP response.
void dhcpsPostAppendOpts(netif* netif,
                         dhcps_t* dhcps,
                         uint8_t state,
                         uint8_t** pp_opts) {
  auto captive{*pp_opts};
  captive[0] = 114;
  sprintf((char*)captive + 2, "http://%s/", inet_ntoa(netif->ip_addr));
  captive[1] = strlen((char*)captive + 2);
  *pp_opts += 2 + captive[1];
  return;
}

// Very simple DNS server that implements a captive portal. We only
// ever respond to queries for A records and then always return the
// IP address of the SoftAP.
static void captivePortalDNS(void* arg) {
  auto ap{(esp_netif_t*)arg};
  // The DNS server never terminates. If it encounters any unexpected
  // failure conditions, it closes the socket and then restarts itself.
  for (int sock;;) {
    for (;;) {
      // Try opening the socket until it succeeds.
      sock = socket(AF_INET, SOCK_DGRAM, 0);
      if (sock >= 0) break;
      vTaskDelay(pdMS_TO_TICKS(1000));
    }
    // Only listen on the IP address of the SoftAP. It shouldn't ever
    // change at run-time, but just to be on the safe side, we reload the
    // IP address every time. For now, we only support IPv4, though.
    esp_netif_ip_info_t info;
    esp_netif_get_ip_info(ap, &info);
    sockaddr_in dnsAddr{
        .sin_len{sizeof(dnsAddr)},
        .sin_family{AF_INET},
        .sin_port{htons(53)},
        .sin_addr{info.ip.addr},
    };
    // If we can't listen on the interface, try again later. Maybe, the SoftAP
    // is (re)intializing.
    if (bind(sock, (sockaddr*)&dnsAddr, sizeof(dnsAddr)) < 0) {
    err:
      close(sock);
      continue;
    }
    // We now have a UDP socket that can listen for DNS requests. We don't
    // worry about TCP. And all we can handle is the most basic DNS requests
    // for a single A record. That should be sufficient to trip "captive
    // portal detection" in all modern browsers.
    for (;;) {
      typedef struct {
        uint16_t id;
        unsigned rd : 1, tc : 1, aa : 1, op : 4, qr : 1;
        unsigned rcode : 4, z : 3, ra : 1;
        uint16_t qdcount, ancount, nscount, arcount;
      } Header;
      sockaddr_in from{};
      socklen_t fromLen{sizeof(from)};
      uint8_t req[200];
      ssize_t len;
      // Read a request and try to parse it as a DNS query.
      if ((len = recvfrom(sock, (uint8_t*)req, sizeof(req), 0, (sockaddr*)&from,
                          &fromLen)) > 0 &&
          fromLen == sizeof(from)) {
        if (len <= sizeof(Header)) continue;
        auto header{(Header*)&req[0]};
        // We only handle packets that contain queries and that aren't
        // truncated. If the packet doesn't meet these requirements, ignore
        // it. There isn't even a need to send an error response for these
        // unexpected packets.
        if (header->tc || header->qr || header->ancount || header->nscount ||
            header->arcount) {
          continue;
        }
        // DNS query compression is a useful feature, but it makes skipping
        // over query strings a little more difficult. We probably don't need
        // to worry too much, since we only handle DNS requests that have a
        // single query and those don't really compress. But we still perform
        // some minimal parsing. Fortunately, full decompression isn't
        // required.
        uint8_t *in{&req[sizeof(Header)]}, *nxt{};
        while (in >= req && in < &req[len]) {
          if (!*in) {
            if (in < &req[len - 1]) nxt = in + 1;
            break;
          } else if ((*in & 0xC0) == 0xC0) {
            if (in < &req[len - 2]) nxt = in + 2;
            break;
          } else
            in += *in + 1;
        }
        if (!nxt) continue;
        // In our response, we claim to be authoritative for everything
        // and we happily offer to perform (fake) recursive look ups.
        header->qr = 1;
        header->aa = 1;
        header->ra = header->rd;
        auto respLen{(uint16_t)len};
        // We can only handle the most basic queries for a single A record.
        if (header->op || header->qdcount != htons(1)) {
          // If there is anything wrong or unexpected, send an error message.
          header->rcode = 4;
        } else {
          // Check whether this is in fact a request for an A record. Also,
          // verify that there is enough space left in our static buffer to
          // compose the response.
          if (&nxt[20] >= &req[sizeof(req)] ||
              (&nxt[4] <= &req[len] && memcmp(nxt, "\0\1\0\1", 4))) {
            // If we can't handle this request, don't even try; we know that
            // our server has lots of limitations. Just send an error message
            // back.
            header->rcode = 4;
          } else {
            // Include the original query and for the response append a
            // pointer to the original host name and an A record referencing
            // the IPv4 address of the SoftAP. You see -- writing a DNS server
            // can be really easy, if we don't really do any look-ups...
            memcpy(&nxt[4], "\xC0\x0C\0\1\0\1\0\0\0\0\0\4", 12);
            memcpy(&nxt[16], &info.ip.addr, 4);
            respLen = &nxt[20] - req;
            header->ancount = htons(1);
          }
        }
        // Send the reply or an error message, in cases when we can't handle
        // the request.
        if (sendto(sock, req, respLen, 0, (sockaddr*)&from, sizeof(from)) !=
            respLen) {
          // There are lots of benign reasons why we might fail to send a
          // response. But we don't need to enumerate all of the possibilities
          // and categorize them. It's easy enough to restart our DNS server.
          // That should fix things (e.g. if the network socket failed).
          goto err;
        }
      } else {
        // We restart when writes fail, but also need to do so for reads.
        goto err;
      }
    }
  }
}

// The hardware only has a single radio. This makes things unreliable if
// trying to operate both AP and STA at the same time, as AP wants to stay on
// a single channel, whereas STA might need to switch channels while actively
// hunting for the base station. We can mitigate a lot of these issues by
// switching between operating modes based on additional knowledge that we
// have.
static wifi_mode_t preferredWiFiMode(NetworkState* state, bool resetSTABlock) {
  // Access to STA connections can be blocked for a while. Unblock, if the
  // caller requested us to do so.
  if (resetSTABlock) {
    state->blockWiFiReconnectsUntil.reset();
  }
  // For now, assume that we always want access to the configuration
  // interface. A future hardening option might make this configurable.
  bool enableAP{true}, enableSTA{false};
  wifi_mode_t mode{};
  ESP_ERROR_CHECK(esp_wifi_get_mode(&mode));
  uint16_t aid{};
  wifi_sta_list_t staList{};

  // Only if we are configured with an SSID (and possibly password) should we
  // even attempt to enable STA mode. Otherwise, things are easy and we stay
  // in AP mode. Also, if somebody is currently attached to our configuration
  // interface, don't attempt switch on STA mode unless explicitly requested.
  // This can knock user's off the SoftAP.
  esp_err_t e0{}, e1{};
  if ((e0 = esp_wifi_ap_get_sta_list(&staList)) != ESP_OK || !staList.num ||
      ((e1 = esp_wifi_sta_get_aid(&aid)) == ESP_OK && aid) ||
      state->tryingNewCredentials == NetworkState::STARTING)
    enableSTA |= (state->staCfg.ssid[0] &&
                  state->blockWiFiReconnectsUntil.isExpired()) ||
                 state->tryingNewCredentials != NetworkState::DONE;
  ESP_LOGI(CONFIG_LWIP_LOCAL_HOSTNAME,
           "e0: %d, e1: %d, sta.num: %d, aid: %d, trying: %d, enableSTA: %s",
           (int)e0, (int)e1, staList.num, (int)aid,
           (int)state->tryingNewCredentials, enableSTA ? "true" : "false");

// Enable the desired mode. But if both AP and STA are disabled, then at the
// very least, turn on AP mode. This allows users to connect to the SoftAP to
// make any necessary configuration changes.
retry:
  auto target =
      enableSTA ? enableAP ? WIFI_MODE_APSTA : WIFI_MODE_STA : WIFI_MODE_AP;
  if (enableSTA) {
    // Temporarily override the default SSID/Password, but fall back to the
    // known-good configuration if we can't connect.
    wifi_sta_config_t tryCfg{state->staCfg};
    if (state->tryingNewCredentials != NetworkState::DONE) {
      memcpy(tryCfg.ssid, state->trySSID, sizeof(state->trySSID));
      memcpy(tryCfg.password, state->tryPSWD, sizeof(state->tryPSWD));
    }
    tryCfg.channel = ssids.preferredChannel(tryCfg.ssid);
    ESP_LOGI(CONFIG_LWIP_LOCAL_HOSTNAME, "Preferred channel: %d",
             tryCfg.channel);
    esp_wifi_set_mode(target);
    if ((!state->sta && !(state->sta = esp_netif_create_default_wifi_sta())) ||
        esp_netif_set_hostname(state->sta, (char*)state->apCfg.ssid) !=
            ESP_OK ||
        esp_wifi_set_config(WIFI_IF_STA, (wifi_config_t*)&tryCfg) != ESP_OK) {
      enableSTA = false;
      goto retry;
    }
  } else
    esp_wifi_set_mode(target);
  return target;
}

// Non-volatile storage must be initialized if using WiFi. Conveniently,
// we can also store WiFi credentials and all sort of other settings in
// NVS storage. It's just a general-purpose key-value store.
static void syncNVS(NetworkState* state, bool update = false) {
  static auto initStatus{ESP_ERR_NOT_FINISHED};
  if (initStatus == ESP_ERR_NOT_FINISHED) initStatus = nvs_flash_init();
  if (initStatus == ESP_ERR_NVS_NO_FREE_PAGES ||
      initStatus == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    nvs_flash_erase();
    initStatus = nvs_flash_init();
  }
  // We store a unique identifier in NVS. This is derived from the main
  // MAC (which is not guaranteed to be unique), and from the limited
  // amount of true randomness that we collected during boot up.
  // We only need to read this information once.
  bool pending = false;
  nvs_handle_t hd{};
  if (nvs_open("default", NVS_READWRITE, &hd) == ESP_OK) {
    if (!update) {
      uint8_t uniqueId[16];
      auto uniqueSz = sizeof(uniqueId);
      if (nvs_get_blob(hd, "uniq", (char*)&uniqueId, &uniqueSz) != ESP_OK) {
        MD5Context md5ctx;
        esp_rom_md5_init(&md5ctx);
        esp_fill_random(uniqueId, sizeof(uniqueId));
        esp_rom_md5_update(&md5ctx, uniqueId, sizeof(uniqueId));
        esp_efuse_mac_get_default(uniqueId);
        esp_rom_md5_update(&md5ctx, uniqueId, sizeof(uniqueId));
        esp_rom_md5_final(uniqueId, &md5ctx);
        nvs_set_blob(hd, "uniq", (char*)uniqueId, uniqueSz);
        pending = true;
      }
      // While we collected 16 bytes of unique identifier, we only use the
      // first six in places such as the host name and the name of the
      // SoftAP.
      ESP_LOGI(CONFIG_LWIP_LOCAL_HOSTNAME,
               "Unique ID: %02X %02X %02X %02X %02X %02X", uniqueId[0],
               uniqueId[1], uniqueId[2], uniqueId[3], uniqueId[4], uniqueId[5]);
      snprintf((char*)state->apCfg.ssid + state->apCfg.ssid_len,
               sizeof(state->apCfg.ssid), "-%02X%02X%02X", uniqueId[0],
               uniqueId[1], uniqueId[2]);
      state->apCfg.ssid_len = strlen((char*)state->apCfg.ssid);
    }
    // If the user previously provided us with WiFi credentials, we can
    // use them to turn on STA mode. Please note that wifi_sta_config_t
    // has ssid and password fields that are zero padded but not
    // necessarily zero terminated.
    // If we are updating NVS information (e.g. after the user changed WiFi
    // credentials) we still read first and then only write in case of a
    // change in value.
    uint8_t ssid[sizeof(state->staCfg.ssid) + 1];
    uint8_t pswd[sizeof(state->staCfg.password) + 1];
    size_t ssidSz{sizeof(ssid) - 1};
    size_t pswdSz{sizeof(pswd) - 1};
    if (nvs_get_blob(hd, "ssid", (char*)&ssid, &ssidSz) == ESP_OK &&
        nvs_get_blob(hd, "pswd", (char*)&pswd, &pswdSz) == ESP_OK) {
    } else {
      // No persistent WiFi credentials found
      ssidSz = pswdSz = 0;
    }
    memset(&ssid[ssidSz], 0, sizeof(ssid) - ssidSz);
    memset(&pswd[pswdSz], 0, sizeof(pswd) - pswdSz);
    if (!update) {
      // Reading credentials from flash into RAM
      memcpy(state->staCfg.ssid, ssid, sizeof(state->staCfg.ssid));
      memcpy(state->staCfg.password, pswd, sizeof(state->staCfg.password));
    } else {
      // Storing new credentials in NVS. Only update data that has changed. This
      // minimizes writes to flash.
      if (memcmp(state->staCfg.ssid, ssid, sizeof(state->staCfg.ssid))) {
        auto ptr =
            (uint8_t*)memchr(state->staCfg.ssid, 0, sizeof(state->staCfg.ssid));
        nvs_set_blob(
            hd, "ssid", state->staCfg.ssid,
            ptr ? ptr - state->staCfg.ssid : sizeof(state->staCfg.ssid));
        pending = true;
      }
      if (memcmp(state->staCfg.password, pswd,
                 sizeof(state->staCfg.password))) {
        auto ptr = (uint8_t*)memchr(state->staCfg.password, 0,
                                    sizeof(state->staCfg.password));
        nvs_set_blob(hd, "pswd", state->staCfg.password,
                     ptr ? ptr - state->staCfg.password
                         : sizeof(state->staCfg.password));
        pending = true;
      }
      if (update && pending)
        ESP_LOGI(CONFIG_LWIP_LOCAL_HOSTNAME,
                 "Storing new WiFi credentials in NVS");
    }
    if (pending) nvs_commit(hd);
    nvs_close(hd);
  }
  return;
}

// Handle WiFi events, such as connections coming up and going down. This is
// essentially the continuation of what initNetwork() does, and it performs a
// few additional initializations that had to wait for the WiFi subsystem to
// fully come up asynchronously.
static void wifiEventHandler(void* arg,
                             esp_event_base_t eventBase,
                             int32_t eventId,
                             void* eventData) {
  auto state{(NetworkState*)arg};
  if (eventBase == WIFI_EVENT) switch (eventId) {
      case WIFI_EVENT_SCAN_DONE:
        ESP_LOGI(CONFIG_LWIP_LOCAL_HOSTNAME, "SCAN_DONE");
        httpd_queue_work(state->httpServer, wifiScanDone, NULL);
        break;
      case WIFI_EVENT_STA_START:
        ESP_LOGI(CONFIG_LWIP_LOCAL_HOSTNAME, "STA_START");
        esp_wifi_connect();
        break;
      case WIFI_EVENT_STA_CONNECTED:
        ESP_LOGI(CONFIG_LWIP_LOCAL_HOSTNAME, "STA_CONNECTED");
        if (state->tryingNewCredentials != NetworkState::DONE) {
          memcpy(state->staCfg.ssid, state->trySSID, sizeof(state->trySSID));
          memcpy(state->staCfg.password, state->tryPSWD,
                 sizeof(state->tryPSWD));
          syncNVS(state, true);
          state->tryingNewCredentials = NetworkState::DONE;
        }
        preferredWiFiMode(state, true);
        break;
      case WIFI_EVENT_STA_DISCONNECTED: {
        ESP_LOGI(CONFIG_LWIP_LOCAL_HOSTNAME, "STA_DISCONNECTED");
        // Trying to connect in STA mode is very disruptive to any client
        // connected in AP mode. So, limit how frequently we are actively
        // trying to connect.
        static esp_timer_handle_t timer{};
        if (!timer) {
          esp_timer_create_args_t args{
              .callback{[](void* arg) {
                // If STA scans are no longer blocked, make another attempt to
                // connect to the base station.
                auto state = (NetworkState*)arg;
                auto mode = preferredWiFiMode(state, false);
                if (mode == WIFI_MODE_APSTA || mode == WIFI_MODE_STA)
                  esp_wifi_connect();
              }},
              .arg{arg},
              .dispatch_method{ESP_TIMER_TASK},
              .name{"sta-connect"}};
          ESP_ERROR_CHECK(esp_timer_create(&args, &timer));
        }
        if (state->tryingNewCredentials != NetworkState::DONE) {
          // If we are actively trying to connect to a new network, do so right
          // away.
          auto mode = preferredWiFiMode(state, true);
          state->tryingNewCredentials =
              state->tryingNewCredentials == NetworkState::STARTING
                  ? NetworkState::TRYING
                  : NetworkState::DONE;
          if (mode == WIFI_MODE_APSTA || mode == WIFI_MODE_STA)
            esp_wifi_connect();
        } else if (!state->blockWiFiReconnectsUntil) {
          // Otherwise, rate-limit attempts to connect, as we otherwise can't
          // keep our SoftAP up and running; and if WiFi credentials don't work,
          // the SoftAP is our only way to recover.
          state->blockWiFiReconnectsUntil = now(29 * 1000);
          ESP_ERROR_CHECK(esp_timer_start_once(timer, 30 * 1000 * 1000));
          auto mode = preferredWiFiMode(state, false);
          if (mode == WIFI_MODE_APSTA || mode == WIFI_MODE_STA)
            esp_wifi_connect();
        }
      } break;
      case WIFI_EVENT_AP_START:
        ESP_LOGI(CONFIG_LWIP_LOCAL_HOSTNAME, "AP_START");
        static TaskHandle_t handle{};
        if (!handle) {
          xTaskCreate(captivePortalDNS, "captivedns", 4096, state->ap,
                      configMAX_PRIORITIES - 1, &handle);
        }
        break;
      case WIFI_EVENT_AP_STACONNECTED:
      case WIFI_EVENT_AP_STADISCONNECTED:
        ESP_LOGI(CONFIG_LWIP_LOCAL_HOSTNAME, "%s",
                 eventId == WIFI_EVENT_AP_STACONNECTED ? "AP_STACONNECTED"
                                                       : "AP_STADISCONNECTED");
        preferredWiFiMode(state, eventId == WIFI_EVENT_AP_STADISCONNECTED);
        break;
      default:
        break;
    }
  return;
}

// Initialize our WiFi network, this can be either in STA or APSTA mode,
// depending on whether we know the WiFi password for the local network
// already.
static void initNetwork() {
  static NetworkState state{
      // Our WiFi settings for both STA (if available) and AP mode.
      .apCfg{.ssid{CONFIG_LWIP_LOCAL_HOSTNAME},
             .ssid_len{sizeof(CONFIG_LWIP_LOCAL_HOSTNAME) - 1},
             .channel{1},
             .authmode{WIFI_AUTH_OPEN},
             .max_connection{2}},
      .staCfg{.scan_method{WIFI_ALL_CHANNEL_SCAN},
              .threshold{.authmode{WIFI_AUTH_OPEN}},
              .pmf_cfg{.capable{true}, .required{false}},
              .failure_retry_cnt{3}}};
  syncNVS(&state);
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK(esp_wifi_init(&cfg));
  bool isSta{!!state.staCfg.ssid[0]};
  if (esp_netif_init() != ESP_OK || esp_event_loop_create_default() != ESP_OK ||
      (isSta && ((state.sta = esp_netif_create_default_wifi_sta()) == NULL ||
                 esp_netif_set_hostname(state.sta, (char*)state.apCfg.ssid) !=
                     ESP_OK)) ||
      (state.ap = esp_netif_create_default_wifi_ap()) == NULL ||
      !(state.httpServer = initHTTPD(&state))) {
    ESP_LOGI(CONFIG_LWIP_LOCAL_HOSTNAME,
             "Something is really wrong with WiFi. Rebooting...");
    reboot();
  }
  httpd_queue_work(
      state.httpServer,
      [](void*) {
        bool isSta{!!state.staCfg.ssid[0]};
        if (esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                                                &wifiEventHandler, &state,
                                                NULL) != ESP_OK ||
            esp_wifi_set_storage(WIFI_STORAGE_RAM) != ESP_OK ||
            esp_wifi_set_mode(isSta ? WIFI_MODE_APSTA : WIFI_MODE_AP) !=
                ESP_OK ||
            (isSta &&
             esp_wifi_set_config(WIFI_IF_STA, (wifi_config_t*)&state.staCfg) !=
                 ESP_OK) ||
            esp_wifi_set_config(WIFI_IF_AP, (wifi_config_t*)&state.apCfg) !=
                ESP_OK ||
            esp_wifi_start() != ESP_OK) {
          ESP_LOGI(CONFIG_LWIP_LOCAL_HOSTNAME,
                   "Something is really wrong with WiFi. Rebooting...");
          reboot();
        }
      },
      NULL);
  return;
}

extern "C" void app_main() {
  // Check if we are running from an unnecessarily large application
  // partition. If so, shrink it now and then reboot. This would happen
  // after the very first time, that new firmware has been flashed or
  // after a successful OTA update.
  if (!inTestAppPartition()) switchPartitionMode(false);

  // Enable WiFi network.
  initNetwork();
  return;

  if (!inTestAppPartition()) {
    // If our partition table is currently not optimal and allocates too
    // much space for the factory application, resize partition sizes
    // now and reboot. This also recreates the data partition after an
    // OTA update has wiped it.
    switchPartitionMode(false);
    // For the purposes of this demo, we keep track of iterations in the
    // RTC RAM area. We go through exactly one cycle of a simulated OTA.
    if (!((bootloader_params_t*)&bootloader_common_get_rtc_retain_mem()->custom)
             ->_[0]++) {
      // In order to perform an OTA, we must move our application out of
      // the way. We temporarily move it into the data partion, which
      // gets wiped in the process.
      ESP_LOGI(CONFIG_LWIP_LOCAL_HOSTNAME,
               "An OTA is available. Move ourselves out of the way");
      switchPartitionMode(true);
    }
  } else {
    // We just successfully completed an OTA and are running in the
    // temporary copy. That's not a good long-term thing to do. Reboot
    // back into the (presumably updated) factory image.
    ESP_LOGI(CONFIG_LWIP_LOCAL_HOSTNAME,
             "We just started in simulated OTA mode; rebooting to "
             "factory mode");
    reboot();
  }
  return;
}