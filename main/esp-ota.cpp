#include <algorithm>
#include <cstring>
#include <iterator>
#include <memory>

#include "esp_app_format.h"
#include "esp_flash_partitions.h"
#include "esp_log.h"
#include "esp_partition.h"
#include "esp_rom_md5.h"
#include "spi_flash_chip_driver.h"

static void shrinkApplication(bool prepareForOTA) {
  // Stack space is precious. Allocate memory from the heap instead when
  // reading larger amounts of data from flash.
  std::unique_ptr<esp_partition_info_t[]> partitions(
      new esp_partition_info_t[ESP_PARTITION_TABLE_MAX_ENTRIES]);
  ESP_LOGI("esp-ota", "Reading partition table from 0x%x",
           CONFIG_PARTITION_TABLE_OFFSET);
  ESP_ERROR_CHECK(esp_flash_read(NULL, partitions.get(),
                                 CONFIG_PARTITION_TABLE_OFFSET,
                                 ESP_PARTITION_TABLE_MAX_LEN));

  // Parse the current partition table. In order for our code to work as
  // intended, the last two partitions must be a "factory" partition followed
  // by the main "data" partition (e.g. a SPIFFS image).
  int8_t appIdx = -1, dataIdx = -1;
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
        assert(dataIdx == -1);
        appIdx = i;
      } else if (entry.type == ESP_PARTITION_TYPE_DATA &&
                 entry.subtype == ESP_PARTITION_SUBTYPE_DATA_SPIFFS) {
        assert(appIdx >= 0);
        assert(dataIdx == -1);
        dataIdx = i;
      }
#if CONFIG_LOG_DEFAULT_LEVEL != LOG_LEVEL_NONE
    } else if (entry.magic == ESP_PARTITION_MAGIC_MD5) {
      // Check the MD5 signature, if present. This code can safely be
      // removed though. There shouldn't be any scenario allowing us to
      // boot into our application with an incorrect signature.
      assert(dataIdx == i - 1);
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
    } else if (entry.magic == 0xFFFF && entry.type == 0xFF &&
               entry.subtype == 0xFF) {
#if CONFIG_LOG_DEFAULT_LEVEL != LOG_LEVEL_NONE
      // The partition table ends, when we find the 0xFFFF end-of-table marker.
      // MD5 signatures can be disabled in the configuration. So, skip the
      // check, if they aren't present.
      ESP_LOGI("esp-ota", "End of partition table, but no MD5 checksum found");
#endif
      assert(dataIdx == i - 1);
      break;
    } else {
      ESP_LOGI("esp-ota", "Corrupted partition table entry");
      abort();
    }
  }
  assert(appIdx >= 0 && dataIdx >= 0);

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
      ESP_LOGI("esp-ota", "Segment %d: len 0x%lx, file offset: 0x%x", i + 1,
               segment.data_len, offset);
      offset += sizeof(segment) + segment.data_len;
    }
    // Image sized must be aligned to 16 bytes.
    offset = (offset + 0xF) & ~0xF;
    // There is an option SHA256 hash at the end of the entire image.
    if (app.hash_appended) offset += 32;
    // Print the information that we have retrieved for our application image.
    ESP_LOGI("esp-ota", "Total image size: %d (0x%x)", offset, offset);
    // The optimal size for our partition is the size of the image rounded up
    // to 64kB.
    size_t optimalSz = (offset + 0xFFFF) & ~0xFFFF;
    ESP_LOGI("esp-ota", "Optimal partition size: %d (0x%x)", optimalSz,
             optimalSz);
    // The data partition takes up the remainder of the flash memory.
    uint32_t flashSz;
    ESP_ERROR_CHECK(esp_flash_get_physical_size(NULL, &flashSz));
    size_t dataSz = flashSz - optimalSz - partitions[appIdx].pos.offset;
    ESP_LOGI("esp-ota", "Maximum data size: %d (0x%x)", dataSz, dataSz);

    // This is where the magic happens. We shrink our application partition to
    // its optimal size, and adjust the size of the data partition accordingly.
    if (partitions[appIdx].pos.size != optimalSz ||
        partitions[dataIdx].pos.size != flashSz - dataSz) {
      partitions[dataIdx].pos.offset -= partitions[appIdx].pos.size - optimalSz;
      partitions[dataIdx].pos.size = flashSz - dataSz;
      partitions[appIdx].pos.size = optimalSz;
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
      // ESP32-IDF tries oh so hard to prevent us from overwriting the
      // partition table. What a fool's errand. It is no match for our grit,
      // determination, and sheer brutal force.
      ESP_LOGI("esp-ota", "Flashing adjusted partition table");
      auto rw = *esp_flash_default_chip;
      auto os_func = *rw.os_func;
      os_func.region_protected = [](void*, size_t, size_t) { return ESP_OK; };
      rw.os_func = &os_func;
      // Flash memory is not like other types of storage. We have to erase it
      // first before we can overwrite it. Remember that it can only be erased
      // in multiples of the sector size (usually 4kB).
      ESP_ERROR_CHECK(esp_flash_erase_region(
          &rw, CONFIG_PARTITION_TABLE_OFFSET,
          (ESP_PARTITION_TABLE_MAX_LEN + rw.chip_drv->sector_size - 1) &
              ~(rw.chip_drv->sector_size - 1)));
      ESP_ERROR_CHECK(esp_flash_write(&rw, partitions.get(),
                                      CONFIG_PARTITION_TABLE_OFFSET,
                                      ESP_PARTITION_TABLE_MAX_LEN));
    }
  }
  return;
}

extern "C" void app_main() {
  shrinkApplication(true);
  return;
}