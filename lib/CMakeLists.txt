# NeoPG - library
# Copyright 2017 The NeoPG developers
#
# NeoPG is released under the Simplified BSD License (see license.txt)

FIND_PACKAGE(Boost COMPONENTS date_time REQUIRED)

# libneopg

set(NEOPG_INCLUDE ../include)

set(NeopgHeaders
  crypto/rng.h
  openpgp/compressed_data_packet.h
  openpgp/literal_data_packet.h
  openpgp/marker_packet.h
  openpgp/modification_detection_code_packet.h
  openpgp/packet_header.h
  openpgp/packet.h
  openpgp/raw_packet.h
  openpgp/symmetrically_encrypted_data_packet.h
  openpgp/symmetrically_encrypted_integrity_protected_data_packet.h
  openpgp/trust_packet.h
  openpgp/user_attribute_packet.h
  openpgp/user_id_packet.h
  parser/openpgp.h
  proto/http.h
  proto/uri.h
  utils/common.h
  utils/stream.h
  utils/time.h
)
add_library(neopg
  include/neopg/intern/cplusplus.h
  crypto/rng.cpp
  openpgp/compressed_data_packet.cpp
  openpgp/literal_data_packet.cpp
  openpgp/marker_packet.cpp
  openpgp/modification_detection_code_packet.cpp
  openpgp/packet_header.cpp
  openpgp/packet.cpp
  openpgp/raw_packet.cpp
  openpgp/symmetrically_encrypted_data_packet.cpp
  openpgp/symmetrically_encrypted_integrity_protected_data_packet.cpp
  openpgp/trust_packet.cpp
  openpgp/user_attribute_packet.cpp
  openpgp/user_id_packet.cpp
  parser/openpgp.cpp
  proto/http.cpp
  proto/uri.cpp
  utils/stream.cpp
  utils/time.cpp
)
target_include_directories(neopg PUBLIC
  "${CMAKE_BINARY_DIR}/include"
  "${CMAKE_CURRENT_SOURCE_DIR}/include"
  ${PEGTL_INCLUDE_DIR}
  ${JSON_INCLUDE_DIR}
  ${Boost_INCLUDE_DIR}
  ${BOTAN2_INCLUDE_DIRS}
  ${CURL_INCLUDE_DIRS}
)

target_compile_options(neopg
  PRIVATE
  -fvisibility=hidden
  ${BOTAN2_CFLAGS_OTHER}
)

target_link_libraries(neopg PUBLIC
${BOTAN2_LDFLAGS} ${BOTAN2_LIBRARIES}
${CURL_LDFLAGS} ${CURL_LIBRARIES}
)

# Publish header files for libneopg
set(NeopgPublishedHeaders "")
set(NeopgPublishedHeadersDir "${CMAKE_BINARY_DIR}/include/neopg")

foreach(Header IN LISTS NeopgHeaders)
  get_filename_component(HeaderFilename "${Header}" NAME)
  set(Output "${NeopgPublishedHeadersDir}/${HeaderFilename}")
  list(APPEND NeopgPublishedHeaders "${Output}")
  add_custom_command(
    OUTPUT "${Output}"
    COMMAND "${CMAKE_COMMAND}" -E
      make_directory "${NeopgPublishedHeadersDir}"
    COMMAND "${CMAKE_COMMAND}" -E
      copy_if_different "${CMAKE_CURRENT_SOURCE_DIR}/${Header}" "${Output}"
    MAIN_DEPENDENCY "${Header}"
    COMMENT "Publishing ${HeaderFilename}"
    VERBATIM
  )
endforeach()
add_custom_target(
  neopg_headers
  DEPENDS ${NeopgPublishedHeaders}
  SOURCES ${NeopgHeaders}
)

add_dependencies(neopg neopg_headers)

add_subdirectory(tests)
