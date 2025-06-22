cmake_minimum_required(VERSION 3.10)
project(ota-fetch C)

set(CMAKE_C_STANDARD 99)

# Find GLib and GIO packages
find_package(PkgConfig REQUIRED)
pkg_check_modules(CURL REQUIRED libcurl)

find_path(CJSON_INCLUDE_DIR cjson/cJSON.h)
find_library(CJSON_LIBRARY cjson)

if(NOT CJSON_INCLUDE_DIR OR NOT CJSON_LIBRARY)
    message(FATAL_ERROR "Could not find cJSON")
endif()

# Define the executable
add_executable(ota-fetch
    src/main.c
    src/ota_fetch.c
    src/config.c
    src/ini.c
    src/manifest.c
)

# Include directories
target_include_directories(ota-fetch PRIVATE
    ${CURL_INCLUDE_DIRS}
    ${CJSON_INCLUDE_DIR}
)

# Compiler flags
target_compile_options(ota-fetch PRIVATE
    -O0
    -g
    -D_FORTIFY_SOURCE=2
    -fstack-protector-strong
)

# Link libraries
target_link_libraries(ota-fetch PRIVATE
    ${CURL_LIBRARIES}
    ${CJSON_LIBRARY}
)

