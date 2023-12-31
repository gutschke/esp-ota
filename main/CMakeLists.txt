if (NOT CMAKE_BUILD_EARLY_EXPANSION)
  add_custom_command(OUTPUT "idx"
                     DEPENDS "${PROJECT_DIR}/main/index.html"
                     COMMAND "${PROJECT_DIR}/main/collapsehtml.py" "${PROJECT_DIR}/main/index.html" "${PROJECT_DIR}/sdkconfig" "idx")
endif()
idf_component_register(SRCS "esp-ota.cpp"
                       INCLUDE_DIRS "."
                       EMBED_TXTFILES "${PROJECT_BINARY_DIR}/main/idx")
add_custom_target(index-html DEPENDS "idx")
add_dependencies(${component_target} index-html)