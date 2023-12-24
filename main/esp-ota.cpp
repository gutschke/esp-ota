#include <cstring>
#include <memory>

#include "bootloader_common.h"
#include "bootloader_params.h"
#include "esp_log.h"
#include "esp_partition.h"
#include "esp_rom_md5.h"
#include "esp_sleep.h"
#include "spi_flash_chip_driver.h"
#include "spi_flash_mmap.h"

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
      new esp_partition_info_t[ESP_PARTITION_TABLE_MAX_ENTRIES]);
  ESP_LOGI("esp-ota", "Reading partition table from 0x%x",
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
      ESP_LOGI("esp-ota", "MD5 digest: %s", buf);
      struct MD5Context md5ctx;
      esp_rom_md5_init(&md5ctx);
      esp_rom_md5_update(&md5ctx, (uint8_t*)partitions.get(),
                         i * sizeof(entry));
      esp_rom_md5_final((uint8_t*)&buf[sizeof(buf) - 16], &md5ctx);
      if (memcmp((uint8_t*)&buf[sizeof(buf) - 16], digest, 16)) {
        for (int i = 0; i < 16; ++i)
          sprintf(&buf[3 * i], "%02X ", buf[sizeof(buf) - 16 + i]);
        ESP_LOGI("esp-ota", "Should be:  %s", buf);
      }
      // Technically, there should be an end-of-table marker after the
      // MD5 signature. We don't enforce this, other than having an assertion
      // that can be compiled-out.
      assert(i < ESP_PARTITION_TABLE_MAX_ENTRIES - 1 &&
             partitions[i + 1].magic == 0xFFFF);
      break;
#endif
    } else if (entry.magic == 0xFFFF) {
#if CONFIG_LOG_DEFAULT_LEVEL != LOG_LEVEL_NONE
      // The partition table ends, when we find the 0xFFFF end-of-table marker.
      // MD5 signatures can be disabled in the configuration. So, skip the
      // check, if they aren't present.
      ESP_LOGI("esp-ota", "End of partition table, but no MD5 checksum found");
#endif
      assert(dataOrTestIdx == i - 1);
      break;
    } else {
      ESP_LOGI("esp-ota", "Corrupted partition table entry");
      abort();
    }
  }
  assert(appIdx >= 0 && dataOrTestIdx >= 0);

  // Parse the application's image file and compute the space required to store
  // it. This requires iterating over the flash information and finding all
  // headers for the various segments mapped into memory.
  esp_image_header_t app;
  auto appOffset = partitions[appIdx].pos.offset;
  ESP_ERROR_CHECK(esp_flash_read(NULL, &app, appOffset, sizeof(app)));
  if (app.magic != ESP_IMAGE_HEADER_MAGIC) {
    ESP_LOGI("esp-ota", "Application image header is corrupt");
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
    ESP_LOGI("esp-ota", "Total image size: %d (0x%x)", offset, offset);
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
    // determination, and sheer brutal force. If nothing else works, we
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
      ESP_LOGI("esp-ota", "Relocate ourselves into the test partition");
      ESP_ERROR_CHECK(esp_flash_erase_region(&rw, appOffset + appSz,
                                             flashSz - appOffset - appSz));
      std::unique_ptr<char[]> sector(new char[sectorSz]);
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
        ESP_LOGI("esp-ota", "Erasing old temporary copy of application");
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
      struct MD5Context md5ctx;
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
      ESP_LOGI("esp-ota", "Flashing new partition table");
      ESP_ERROR_CHECK(
          esp_flash_erase_region(&rw, CONFIG_PARTITION_TABLE_OFFSET,
                                 (ESP_PARTITION_TABLE_MAX_LEN + sectorSz - 1) &
                                     ~(rw.chip_drv->sector_size - 1)));
      ESP_ERROR_CHECK(esp_flash_write(&rw, partitions.get(),
                                      CONFIG_PARTITION_TABLE_OFFSET,
                                      ESP_PARTITION_TABLE_MAX_LEN));
      ESP_LOGI(
          "esp-ota", "%s",
          enableOTAMode
              ? "Adjusted partition table, copied app, now rebooting for OTA"
              : "Adjusted partition table, rebooting now for the changes to "
                "take effect");
      reboot(enableOTAMode ? TEST_APP_INDEX : FACTORY_INDEX);
    } else if (enableOTAMode) {
      ESP_LOGI("esp-ota",
               "The partition table looks fine, but rebooting for OTA");
      reboot(TEST_APP_INDEX);
    }
  }
  ESP_LOGI("esp-ota", "Everything looks good, nothing to do right now...");
  return;
}

extern "C" void app_main() {
  if (!inTestAppPartition()) {
    // If our partition table is currently not optimal and allocates too much
    // space for the factory application, resize partition sizes now and reboot.
    // This also recreates the data partition after an OTA update has wiped it.
    switchPartitionMode(false);
    // For the purposes of this demo, we keep track of iterations in the RTC
    // RAM area. We go through exactly one cycle of a simulated OTA.
    if (!((bootloader_params_t*)&bootloader_common_get_rtc_retain_mem()->custom)
             ->_[0]++) {
      // In order to perform an OTA, we must move our application out of the
      // way. We temporarily move it into the data partion, which gets wiped
      // in the process.
      ESP_LOGI("esp-ota", "An OTA is available. Move ourselves out of the way");
      switchPartitionMode(true);
    }
  } else {
    // We just successfully completed an OTA and are running in the temporary
    // copy. That's not a good long-term thing to do. Reboot back into the
    // (presumably updated) factory image.
    ESP_LOGI(
        "esp-ota",
        "We just started in simulated OTA mode; rebooting to factory mode");
    reboot();
  }
  return;
}