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

// Pass state from the event handler to the network-related tasks.
struct NetworkState {
  esp_netif_t *ap, *sta;
};

// Notify web socket connections of WiFi scan results.
static bool wifiScanning{false};
static std::map<httpd_handle_t, int> wsSessions;

// Our WiFi settings for both STA (if available) and AP mode.
static wifi_config_t wifiStaConfig{
    .sta{.scan_method{WIFI_ALL_CHANNEL_SCAN},
         .threshold{.authmode{WIFI_AUTH_WPA_PSK}},
         .pmf_cfg = {.capable{true}, .required{false}}},
};
static wifi_config_t wifiApConfig{
    .ap = {.ssid{CONFIG_LWIP_LOCAL_HOSTNAME},
           .ssid_len{strlen(CONFIG_LWIP_LOCAL_HOSTNAME)},
           .channel{1},
           .authmode{WIFI_AUTH_OPEN},
           .max_connection{2}}};

// The standard boot loader implements a relatively rigid policy for
// determining the boot partition. We extended it so that we can boot
// into other partitions on demand. Unlike the default OTA mechanism,
// we don't persist this selection. After power-cycling, we would
// follow the default boot order, which prefers the "factory" image
// unless it is damaged. In that case, it executes the "test" image.
static void reboot(uint32_t target = FACTORY_INDEX) {
  bootloader_params_t* params =
      (bootloader_params_t*)&bootloader_common_get_rtc_retain_mem()->custom;
  params->partition_index = target;
  esp_deep_sleep(1000 /* 1 ms */);
}

// We create a temporary "test" image when preparing for OTA updates.
// Check whether we are running in that partition or instead in the
// regular "factory" partition.
static bool inTestAppPartition() {
  auto me = spi_flash_cache2phys((void*)inTestAppPartition);
  auto part = esp_partition_find_first(ESP_PARTITION_TYPE_APP,
                                       ESP_PARTITION_SUBTYPE_APP_FACTORY, NULL);
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
  std::unique_ptr<esp_partition_info_t[]> partitions(
      new (std::nothrow) esp_partition_info_t[ESP_PARTITION_TABLE_MAX_ENTRIES]);
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
  int8_t appIdx = -1, dataOrTestIdx = -1;
  bool inOTAMode = false;
  for (auto i = 0; i < ESP_PARTITION_TABLE_MAX_ENTRIES; ++i) {
    const esp_partition_info_t& entry = partitions[i];
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
        const auto me = spi_flash_cache2phys((void*)switchPartitionMode);
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
      const uint8_t* digest = (uint8_t*)&entry + 16;
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
  auto appOffset = partitions[appIdx].pos.offset;
  ESP_ERROR_CHECK(esp_flash_read(NULL, &app, appOffset, sizeof(app)));
  if (app.magic != ESP_IMAGE_HEADER_MAGIC) {
    ESP_LOGI(CONFIG_LWIP_LOCAL_HOSTNAME, "Application image header is corrupt");
  } else {
    // The image size is the total of the image header, all combined segment
    // headers, and the data in each segment.
    auto offset = sizeof(app);
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
    size_t appSz = (offset + 0xFFFF) & ~0xFFFF;
    // In production mode, the optimal application size is the same as the
    // properly padded size of the image. In OTA mode, the application
    // should take up as much space as possible, leaving just enough room at
    // the top of the flash for the "test" partition.
    uint32_t flashSz;
    ESP_ERROR_CHECK(esp_flash_get_physical_size(NULL, &flashSz));
    size_t optimalSz = enableOTAMode ? flashSz - appOffset - appSz : appSz;
    // The data partition takes up the remainder of the flash memory.
    size_t dataOrTestSz = flashSz - optimalSz - appOffset;
    // ESP32-IDF tries oh so hard to prevent us from overwriting the
    // partition table. What a valiant effort, but its struggles as all things
    // are ultimately doomed to failure. It is no match for our grit,
    // determination, and sheer brute force. If nothing else works, we
    // simply define our own flash chip.
    auto rw = *esp_flash_default_chip;
    auto os_func = *rw.os_func;
    os_func.region_protected = [](void*, size_t, size_t) { return ESP_OK; };
    rw.os_func = &os_func;
    const auto sectorSz = esp_flash_default_chip->chip_drv->sector_size;
    // If we want to perform an OTA update momentarily, we have to make sure we
    // execute code from somewhere other than where we are going to write.
    // Temporarily, relocate ourselves to the data partition, overwritting
    // whatever might reside there.
    if (enableOTAMode && !inOTAMode) {
      ESP_LOGI(CONFIG_LWIP_LOCAL_HOSTNAME,
               "Relocate ourselves into the test partition");
      ESP_ERROR_CHECK(esp_flash_erase_region(&rw, appOffset + appSz,
                                             flashSz - appOffset - appSz));
      std::unique_ptr<char[]> sector(new (std::nothrow) char[sectorSz]);
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

// The number of web socket listeners has changed. Update the WiFi scan mode.
static void wifiScanner() {
  const bool hasListeners = !!wsSessions.size();
  if (wifiScanning != hasListeners) {
    wifiScanning = hasListeners;
    if (wifiScanning) {
      wifi_scan_config_t cfg{.show_hidden{false},
                             .scan_type{WIFI_SCAN_TYPE_ACTIVE},
                             .scan_time{.active{.max{100}}},
                             .home_chan_dwell_time{250}};
      esp_wifi_scan_start(&cfg, false);
    } else
      esp_wifi_scan_stop();
  }
  return;
}

// Checks whether the client connected to our AP which is used for the
// configuration GUI, or whether our HTTP server is operating in STA mode. In
// that case, we don't expose the configuration interface.
static bool clientConnectedToAP(httpd_req_t* req) {
  auto fd = httpd_req_to_sockfd(req);
  sockaddr_in6 in;
  socklen_t inLen = sizeof(in);
  if (!getsockname(fd, (sockaddr*)&in, &inLen)) {
    auto ap = ((NetworkState*)req->user_ctx)->ap;
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
  auto fd = httpd_req_to_sockfd(req);
  sockaddr_in6 in;
  socklen_t len = sizeof(in);
  if (!getsockname(fd, (sockaddr*)&in, &len)) {
    char buf[40 + sizeof(CONFIG_LWIP_LOCAL_HOSTNAME)];
    snprintf(buf, sizeof(buf), "http://%s/%s",
             inet_ntop(AF_INET, &in.sin6_addr.un.u32_addr[3],
                       &buf[sizeof(buf) - 16], 16),
             path);
    httpd_resp_set_hdr(req, "Location", buf);
  }
  return httpd_resp_send(req, NULL, 0);
}

// We asked the web socket subsystem to send us control messages. That means, we
// are now responsible to actually respond to them.
static esp_err_t maybeHandleWSCtrl(httpd_req_t* req,
                                   httpd_ws_type_t* type = 0,
                                   char** buf = 0,
                                   size_t* len = 0) {
  // Check if this is even web socket connection in the first place. The caller
  // shouldn't have called us otherwise.
  if (buf) *buf = NULL;
  if (len) *len = 0;
  if (type) *type = (httpd_ws_type_t)-1;
  if (req->method) {
    return ESP_ERR_INVALID_STATE;
  }
  // Prepare to load the web socket payload;
  httpd_ws_frame_t wsPacket = {.type = HTTPD_WS_TYPE_TEXT};
  auto rc = httpd_ws_recv_frame(req, &wsPacket, 0);
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
    default:
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

// The web server for the configuration GUI supports both GET requests for
// static embedded files and web socket requests for configuration management.
static esp_err_t cfgHttpHandler(httpd_req_t* req) {
  if (req->method == HTTP_GET) {
    // If this is an HTTP connection in the process of being upgraded to a web
    // socket connection, we shouldn't try to return any data for the request.
    // It's just going to mess up the web socket.
    auto rc =
        httpd_req_get_hdr_value_str(req, "Sec-WebSocket-Protocol", NULL, 0);
    if (rc == ESP_OK || rc == ESP_ERR_HTTPD_RESULT_TRUNC) {
#ifdef __EXCEPTIONS
      try {
#endif
        wsSessions[req->handle] = httpd_req_to_sockfd(req);
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
    } files[] = {
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
  auto rc = maybeHandleWSCtrl(req, &type, &buf, &len);
  switch (type) {
    case HTTPD_WS_TYPE_CLOSE:
      wsSessions.erase(req->handle);
      wifiScanner();
      break;
    case HTTPD_WS_TYPE_TEXT:
    case HTTPD_WS_TYPE_BINARY:
      break;
    default:
      break;
  }
  free(buf);
  return rc;
}

// Immediately reset all requests arriving on port 443. That's good enough to
// make browsers give up on automatically upgrading captive portals to HTTPS.
static void reset443(void* arg) {
  auto ap = (esp_netif_t*)arg;
  for (int sock;;) {
    for (;;) {
      // Try opening the socket until it succeeds.
      sock = socket(AF_INET, SOCK_STREAM, 0);
      if (sock >= 0) break;
      vTaskDelay(pdMS_TO_TICKS(1000));
    }
    // Only listen on the IP address of the SoftAP. It shouldn't ever
    // change at run-time, but just to be on the safe side, we reload the
    // IP address if every time. For now, we only support IPv4, though.
    esp_netif_ip_info_t info;
    esp_netif_get_ip_info(ap, &info);
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
      continue;
    }
    for (int fd;;) {
      if (listen(sock, 5) || (fd = accept(sock, 0, 0)) < 0) goto err;
      close(fd);
    }
  }
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
  bool forceApp = false, forceCfg = false;
  const auto uri = req->uri;
  if (*uri == '/' && !memcmp(uri + 1, CONFIG_LWIP_LOCAL_HOSTNAME,
                             sizeof(CONFIG_LWIP_LOCAL_HOSTNAME))) {
    size_t removeCount = sizeof(CONFIG_LWIP_LOCAL_HOSTNAME) - 1;
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
  bool onSoftAP = clientConnectedToAP(req);
  // If accessing through the SoftAP (which defaults to showing the
  // configuration GUI upon power on), permanently switch to the main
  // application the first time it gets access. This can be reset by power
  // cycling. Or of course, the user can always explicitly decide to go to
  // "${APP}-app".
  static bool appEnabled = false;
  appEnabled |= onSoftAP && forceApp;
  // There are several conditions that make us display the main app, and a
  // few that make us display the configuration GUI. Of course, all of this is
  // moot, if there isn't even a main app registered.
  if ((appEnabled || !onSoftAP || forceApp) && !forceCfg)
    if (mainAppHttpHandler) {
      // We asked the web socket subsystem to send us control messages. This
      // means we are responsible for implementing them. The main application
      // might not know how to do so, though.
      return mainAppHttpHandler(req);
    }
  return cfgHttpHandler(req);
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
static void initHTTPD(NetworkState* state) {
  const auto matchAll = [](const char*, const char*, size_t) { return true; };
  httpd_config_t cfg = HTTPD_DEFAULT_CONFIG();
  cfg.uri_match_fn = matchAll;
  cfg.enable_so_linger = true;
  cfg.close_fn = [](httpd_handle_t hd, int fd) {
    wsSessions.erase(hd);
    close(fd);
    wifiScanner();
  };
  httpd_handle_t httpServer = NULL;
  if (!httpd_start(&httpServer, &cfg)) {
    httpd_uri_t handler{.uri = "",
                        .method = HTTP_GET,
                        .handler = httpHandler,
                        .user_ctx = state,
                        .is_websocket = true,
                        .handle_ws_control_frames = true,
                        .supported_subprotocol = "cfg"};
    httpd_register_uri_handler(httpServer, &handler);
  }
  const auto alwaysRedirect = [](httpd_req* req, httpd_err_code_t err) {
    return redirectHandler(req);
  };
  for (auto err = httpd_err_code_t{}; err < HTTPD_ERR_CODE_MAX;
       err = (httpd_err_code_t)((int)err + 1)) {
    httpd_register_err_handler(httpServer, err, alwaysRedirect);
  }
  xTaskCreate(reset443, "fakehttps", 2048, state->ap, configMAX_PRIORITIES - 1,
              0);
  return;
}

// Advertise our own IP address as a captive portal in the DHCP response.
void dhcpsPostAppendOpts(netif* netif,
                         dhcps_t* dhcps,
                         uint8_t state,
                         uint8_t** pp_opts) {
  auto captive = *pp_opts;
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
  auto ap = (esp_netif_t*)arg;
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
    // IP address if every time. For now, we only support IPv4, though.
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
        unsigned rd : 1;
        unsigned tc : 1;
        unsigned aa : 1;
        unsigned op : 4;
        unsigned qr : 1;
        unsigned rcode : 4;
        unsigned z : 3;
        unsigned ra : 1;
        uint16_t qdcount;
        uint16_t ancount;
        uint16_t nscount;
        uint16_t arcount;
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
        auto& header = *(Header*)&req[0];
        // We only handle packets that contain queries and that aren't
        // truncated. If the packet doesn't meet these requirements, ignore
        // it. There isn't even a need to send an error response for these
        // unexpected packets.
        if (header.tc || header.qr || header.ancount || header.nscount ||
            header.arcount) {
          continue;
        }
        // DNS query compression is a useful feature, but it makes skipping
        // over query strings a little more difficult. We probably don't need
        // to worry too much, since we only handle DNS requests that have a
        // single query and those don't really compress. But we still perform
        // some minimal parsing. Fortunately, full decompression isn't
        // required.
        uint8_t *in = &req[sizeof(Header)], *nxt = 0;
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
        header.qr = 1;
        header.aa = 1;
        header.ra = header.rd;
        uint16_t respLen = len;
        // We can only handle the most basic queries for a single A record.
        if (header.op || header.qdcount != htons(1)) {
          // If there is anything wrong or unexpected, send an error message.
          header.rcode = 4;
        } else {
          // Check whether this is in fact a request for an A record. Also,
          // verify that there is enough space left in our static buffer to
          // compose the response.
          if (&nxt[20] >= &req[sizeof(req)] ||
              (&nxt[4] <= &req[len] && memcmp(nxt, "\0\1\0\1", 4))) {
            // If we can't handle this request, don't even try; we know that
            // our server has lots of limitations. Just send an error message
            // back.
            header.rcode = 4;
          } else {
            // Include the original query and for the response append a
            // pointer to the original host name and an A record referencing
            // the IPv4 address of the SoftAP. You see -- writing a DNS server
            // can be really easy, if we don't really do any look-ups...
            memcpy(&nxt[4], "\xC0\x0C\0\1\0\1\0\0\0\0\0\4", 12);
            memcpy(&nxt[16], &info.ip.addr, 4);
            respLen = &nxt[20] - req;
            header.ancount = htons(1);
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

// Handle WiFi events, such as connections coming up and going down. This is
// essentially the continuation of what initNetwork() does, and it performs a
// few additional initializations that had to wait for the WiFi subsystem to
// fully come up asynchronously.
template <typename T>
struct CaseInsensitiveLess {
  bool operator()(T lhs, T rhs) const {
    return strcasecmp((char*)lhs.data(), (char*)rhs.data()) < 0;
  }
};
static void wifiEventHandler(void* arg,
                             esp_event_base_t eventBase,
                             int32_t eventId,
                             void* eventData) {
  const auto& state = *(NetworkState*)arg;
  if (eventBase == WIFI_EVENT) switch (eventId) {
      case WIFI_EVENT_SCAN_DONE: {
        uint16_t num;
        wifi_ap_record_t* records = NULL;
        if (esp_wifi_scan_get_ap_num(&num) == ESP_OK) {
          // We have to allocate enough space to hold all search results. But
          // even if the allocation fails, we must call
          // esp_wifi_scan_get_ap_records() to clean up resources. Error
          // handling is tricky here.
          if (!(records = (wifi_ap_record_t*)malloc(num * sizeof(*records))))
            num = 0;
          if (esp_wifi_scan_get_ap_records(&num, records) == ESP_OK && num) {
            static std::map<
                std::array<uint8_t, MAX_SSID_LEN + 1>, uint8_t,
                CaseInsensitiveLess<std::array<uint8_t, MAX_SSID_LEN + 1> > >
                ssids;
            httpd_ws_frame_t wsPacket = {.type{HTTPD_WS_TYPE_TEXT}, .len{0}};
#ifdef __EXCEPTIONS
            try {
#endif
              static uint8_t generation{0};
              generation++;
              for (int i = 0; i < num; ++i)
                if (*records[i].ssid)
                  ssids[std::to_array(records[i].ssid)] = generation;
              for (auto it = ssids.begin(); it != ssids.end();) {
                // We do eventually remove stale WiFi access points when they
                // no longer show up in scans. But since scans are notoriously
                // unreliable, we err on the side of caching old data for
                // quite a while.
                if (generation - it->second > 10)
                  it = ssids.erase(it);
                else
                  wsPacket.len += 1 + strlen((char*)it++->first.data());
              }
              if (!!(wsPacket.payload = (uint8_t*)malloc(wsPacket.len))) {
                auto ptr = (char*)wsPacket.payload;
                for (auto it = ssids.begin(); it != ssids.end(); ++it) {
                  ptr += 1 + strlen(strcpy(ptr, (char*)it->first.data()));
                }
                // Sending a message on a web socket can trigger events that
                // end up marking the session as closed. This can cause us to
                // modify the "wsSessions" map concurrently with iterating
                // over it. Create a copy of the map first and then verify
                // that the global map still contains our session before
                // operating on it.
                auto cpy{wsSessions};
                for (auto it = cpy.begin(); it != cpy.end(); ++it) {
                  const auto old = wsSessions.find(it->first);
                  if (old != wsSessions.end() && old->second == it->second)
                    httpd_ws_send_data(it->first, it->second, &wsPacket);
                }
              }
#ifdef __EXCEPTIONS
            } catch (const std::bad_alloc&) {
              ssids.clear();
            }
#endif
            free(wsPacket.payload);
          }
        }
        free(records);
        wifiScanning = false;
        wifiScanner();
      } break;
      case WIFI_EVENT_STA_START:
        esp_wifi_connect();
        break;
      case WIFI_EVENT_STA_DISCONNECTED: {
        wifi_sta_list_t sta{};
        if (esp_wifi_ap_get_sta_list(&sta) != ESP_OK || !sta.num)
          esp_wifi_connect();
      } break;
      case WIFI_EVENT_AP_START:
        static TaskHandle_t handle = 0;
        if (!handle) {
          xTaskCreate(captivePortalDNS, "captivedns", 4096, state.ap,
                      configMAX_PRIORITIES - 1, &handle);
        }
        break;
      case WIFI_EVENT_AP_STACONNECTED:
      case WIFI_EVENT_AP_STADISCONNECTED: {
        // The ESP32 only has a single radio. This means, while scanning for
        // WiFi networks to connect to in STA mode, it can't reliably maintain
        // connections in AP mode. As a work-around, we leave APSTA mode in
        // favor of plain AP mode, whenever somebody is connected to our
        // SoftAP. On the other hand, if there is a working WiFi connection in
        // both WiFi modes, no need to stop APSTA, as we aren't expected to
        // start scanning.
        wifi_mode_t mode{};
        wifi_sta_list_t sta{};
        wifi_ap_record_t ap{};
        if (esp_wifi_get_mode(&mode) == ESP_OK &&
            esp_wifi_ap_get_sta_list(&sta) == ESP_OK) {
          bool online = esp_wifi_sta_get_ap_info(&ap) == ESP_OK;
          wifi_mode_t target =
              sta.num && !online ? WIFI_MODE_AP : WIFI_MODE_APSTA;
          ESP_LOGI(CONFIG_LWIP_LOCAL_HOSTNAME,
                   "Currently in %s mode, %d clients are connected to us and "
                   "we are %sonline",
                   mode == WIFI_MODE_APSTA ? "APSTA" : "AP", sta.num,
                   online ? "" : "not ");
          if (target != mode) {
            ESP_LOGI(CONFIG_LWIP_LOCAL_HOSTNAME, "Changing WiFi mode to %s",
                     target == WIFI_MODE_APSTA ? "APSTA" : "AP");
            esp_wifi_set_mode(target);
          }
        }
      } break;
      default:
        break;
    }
  return;
}

// Initialize our WiFi network, this can be either in STA or APSTA mode,
// depending on whether we know the WiFi password for the local network
// already.
static void initNetwork() {
  static NetworkState state{};
  bool isSta = !!wifiStaConfig.sta.ssid[0];
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  if (esp_netif_init() != ESP_OK || esp_event_loop_create_default() != ESP_OK ||
      esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                                          &wifiEventHandler, &state,
                                          NULL) != ESP_OK ||
      (isSta && ((state.sta = esp_netif_create_default_wifi_sta()) == NULL ||
                 esp_netif_set_hostname(
                     state.sta, (char*)wifiApConfig.ap.ssid) != ESP_OK)) ||
      (state.ap = esp_netif_create_default_wifi_ap()) == NULL ||
      esp_wifi_init(&cfg) != ESP_OK ||
      esp_wifi_set_storage(WIFI_STORAGE_RAM) != ESP_OK ||
      esp_wifi_set_mode(isSta ? WIFI_MODE_APSTA : WIFI_MODE_AP) != ESP_OK ||
      (isSta && esp_wifi_set_config(WIFI_IF_STA, &wifiStaConfig) != ESP_OK) ||
      esp_wifi_set_config(WIFI_IF_AP, &wifiApConfig) != ESP_OK ||
      esp_wifi_start() != ESP_OK) {
    ESP_LOGI(CONFIG_LWIP_LOCAL_HOSTNAME,
             "Something is really wrong with WiFi. Rebooting...");
    reboot();
  }
  initHTTPD(&state);
  return;
}

// Non-volatile storage must be initialized if using WiFi. Conveniently, we
// can also store WiFi credentials and all sort of other settings in NVS
// storage. It's just a general-purpose key-value store.
static void initNVS() {
  const auto initStatus = nvs_flash_init();
  if (initStatus == ESP_ERR_NVS_NO_FREE_PAGES ||
      initStatus == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    nvs_flash_erase();
    nvs_flash_init();
  }
  // If the user previously provided us with WiFi credentials, we can use them
  // to turn on STA mode.
  nvs_handle_t hd = 0;
  auto& ssid = wifiStaConfig.sta.ssid;
  auto& pswd = wifiStaConfig.sta.password;
  auto ssidSz = sizeof(ssid) - 1;
  auto pswdSz = sizeof(pswd) - 1;
  if (nvs_open("default", NVS_READWRITE, &hd) == ESP_OK &&
      nvs_get_blob(hd, "ssid", (char*)&ssid, &ssidSz) == ESP_OK &&
      nvs_get_blob(hd, "pswd", (char*)&pswd, &pswdSz) == ESP_OK) {
    ssid[ssidSz] = pswd[pswdSz] = '\000';
  }
  // We store a unique identifier in NVS. This is derived from the main MAC
  // (which is not guaranteed to be unique), and from the limited amount of
  // true randomness that we collected during boot up.
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
    nvs_commit(hd);
    // While we collected 16 bytes of unique identifier, we only use the first
    // six in places such as the host name and the name of the SoftAP.
    ESP_LOGI(CONFIG_LWIP_LOCAL_HOSTNAME,
             "Unique ID: %02X %02X %02X %02X %02X %02X", uniqueId[0],
             uniqueId[1], uniqueId[2], uniqueId[3], uniqueId[4], uniqueId[5]);
  }
  snprintf((char*)wifiApConfig.ap.ssid + wifiApConfig.ap.ssid_len,
           sizeof(wifiApConfig.ap.ssid), "-%02X%02X%02X", uniqueId[0],
           uniqueId[1], uniqueId[2]);
  wifiApConfig.ap.ssid_len = strlen((char*)wifiApConfig.ap.ssid);
  if (hd) {
    nvs_close(hd);
  }
  return;
}

extern "C" void app_main() {
  // Check if we are running from an unnecessarily large application
  // partition. If so, shrink it now and then reboot. This would happen after
  // the very first time, that new firmware has been flashed or after a
  // successful OTA update.
  if (!inTestAppPartition()) switchPartitionMode(false);

  // Enable WiFi network.
  initNVS();
  initNetwork();

  if (!inTestAppPartition()) {
    // If our partition table is currently not optimal and allocates too much
    // space for the factory application, resize partition sizes now and
    // reboot. This also recreates the data partition after an OTA update has
    // wiped it.
    switchPartitionMode(false);
    // For the purposes of this demo, we keep track of iterations in the RTC
    // RAM area. We go through exactly one cycle of a simulated OTA.
    if (!((bootloader_params_t*)&bootloader_common_get_rtc_retain_mem()->custom)
             ->_[0]++) {
      // In order to perform an OTA, we must move our application out of the
      // way. We temporarily move it into the data partion, which gets wiped
      // in the process.
      ESP_LOGI(CONFIG_LWIP_LOCAL_HOSTNAME,
               "An OTA is available. Move ourselves out of the way");
      switchPartitionMode(true);
    }
  } else {
    // We just successfully completed an OTA and are running in the temporary
    // copy. That's not a good long-term thing to do. Reboot back into the
    // (presumably updated) factory image.
    ESP_LOGI(
        CONFIG_LWIP_LOCAL_HOSTNAME,
        "We just started in simulated OTA mode; rebooting to factory mode");
    reboot();
  }
  return;
}