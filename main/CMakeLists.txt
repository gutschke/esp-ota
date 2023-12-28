if (NOT CMAKE_BUILD_EARLY_EXPANSION)
  add_custom_command(OUTPUT "cert.pem" "key.pem"
                     COMMAND openssl req -newkey rsa:2048 -nodes -keyout "key.pem" -x509 -days 36500 -out "cert.pem" -subj "/CN=Microcontroller"
                     VERBATIM)
endif()
idf_component_register(SRCS "esp-ota.cpp"
                       INCLUDE_DIRS "."
                       EMBED_FILES "index.html"
                       EMBED_TXTFILES "${PROJECT_BINARY_DIR}/main/cert.pem" "${PROJECT_BINARY_DIR}/main/key.pem"
                       )
add_custom_target(certs DEPENDS "cert.pem" "key.pem")
add_dependencies(${component_target} certs)