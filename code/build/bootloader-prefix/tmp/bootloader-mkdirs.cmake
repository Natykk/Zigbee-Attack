# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION 3.5)

file(MAKE_DIRECTORY
  "/home/gauteron-nathan/esp/v5.3.1/esp-idf/components/bootloader/subproject"
  "/home/gauteron-nathan/Téléchargements/esp-zigbee-sdk-main/examples/esp_zigbee_all_device_types_app/build/bootloader"
  "/home/gauteron-nathan/Téléchargements/esp-zigbee-sdk-main/examples/esp_zigbee_all_device_types_app/build/bootloader-prefix"
  "/home/gauteron-nathan/Téléchargements/esp-zigbee-sdk-main/examples/esp_zigbee_all_device_types_app/build/bootloader-prefix/tmp"
  "/home/gauteron-nathan/Téléchargements/esp-zigbee-sdk-main/examples/esp_zigbee_all_device_types_app/build/bootloader-prefix/src/bootloader-stamp"
  "/home/gauteron-nathan/Téléchargements/esp-zigbee-sdk-main/examples/esp_zigbee_all_device_types_app/build/bootloader-prefix/src"
  "/home/gauteron-nathan/Téléchargements/esp-zigbee-sdk-main/examples/esp_zigbee_all_device_types_app/build/bootloader-prefix/src/bootloader-stamp"
)

set(configSubDirs )
foreach(subDir IN LISTS configSubDirs)
    file(MAKE_DIRECTORY "/home/gauteron-nathan/Téléchargements/esp-zigbee-sdk-main/examples/esp_zigbee_all_device_types_app/build/bootloader-prefix/src/bootloader-stamp/${subDir}")
endforeach()
if(cfgdir)
  file(MAKE_DIRECTORY "/home/gauteron-nathan/Téléchargements/esp-zigbee-sdk-main/examples/esp_zigbee_all_device_types_app/build/bootloader-prefix/src/bootloader-stamp${cfgdir}") # cfgdir has leading slash
endif()
