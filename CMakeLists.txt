# For more information about build system see
# https://docs.espressif.com/projects/esp-idf/en/latest/api-guides/build-system.html
# The following five lines of boilerplate have to be in your project's
# CMakeLists in this exact order for cmake to work correctly
cmake_minimum_required(VERSION 3.16)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(esp-ota)
idf_component_get_property(lwip lwip COMPONENT_LIB)
target_compile_definitions(${lwip} PRIVATE "-DESP_IDF_LWIP_HOOK_FILENAME=\"${PROJECT_DIR}/main/dhcp-options.h\"")
add_custom_target(resizepartitions
                  DEPENDS gen_project_binary partition_table_bin
                  COMMAND "${PROJECT_DIR}/main/resizepartitions.py" "${PROJECT_BINARY_DIR}/partition_table/partition-table.bin" "${PROJECT_BINARY_DIR}/${PROJECT_NAME}.bin")
add_dependencies(bootloader resizepartitions)