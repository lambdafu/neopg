# NeoPG - library
# Copyright 2017 The NeoPG developers
#
# NeoPG is released under the Simplified BSD License (see license.txt)

# libneopg

add_library(neopg
  crypto/rng.cpp
  include/neopg/intern/cplusplus.h
  openpgp/compressed_data_packet.cpp
  openpgp/literal_data_packet.cpp
  openpgp/marker_packet.cpp
  openpgp/modification_detection_code_packet.cpp
  openpgp/multiprecision_integer.cpp
  openpgp/object_identifier.cpp
  openpgp/packet.cpp
  openpgp/packet_header.cpp
  openpgp/public_key_packet.cpp
  openpgp/public_key/data/v3_public_key_data.cpp
  openpgp/public_key/data/v4_public_key_data.cpp
  openpgp/public_key/material/dsa_public_key_material.cpp
  openpgp/public_key/material/ecdh_public_key_material.cpp
  openpgp/public_key/material/ecdsa_public_key_material.cpp
  openpgp/public_key/material/eddsa_public_key_material.cpp
  openpgp/public_key/material/elgamal_public_key_material.cpp
  openpgp/public_key/material/raw_public_key_material.cpp
  openpgp/public_key/material/rsa_public_key_material.cpp
  openpgp/public_key/public_key_data.cpp
  openpgp/public_key/public_key_material.cpp
  openpgp/public_subkey_packet.cpp
  openpgp/raw_packet.cpp
  openpgp/signature_packet.cpp
  openpgp/signature/data/v3_signature_data.cpp
  openpgp/signature/data/v4_signature_data.cpp
  openpgp/signature/data/v4_signature_subpacket_data.cpp
  openpgp/signature/material/raw_signature_material.cpp
  openpgp/signature/material/rsa_signature_material.cpp
  openpgp/signature/material/dsa_signature_material.cpp
  openpgp/signature/material/ecdsa_signature_material.cpp
  openpgp/signature/material/eddsa_signature_material.cpp
  openpgp/signature/signature_data.cpp
  openpgp/signature/signature_material.cpp
  openpgp/signature/signature_subpacket.cpp
  openpgp/signature/subpacket/embedded_signature_subpacket.cpp
  openpgp/signature/subpacket/exportable_certification_subpacket.cpp
  openpgp/signature/subpacket/features_subpacket.cpp
  openpgp/signature/subpacket/issuer_subpacket.cpp
  openpgp/signature/subpacket/key_expiration_time_subpacket.cpp
  openpgp/signature/subpacket/key_flags_subpacket.cpp
  openpgp/signature/subpacket/key_server_preferences_subpacket.cpp
  openpgp/signature/subpacket/notation_data_subpacket.cpp
  openpgp/signature/subpacket/policy_uri_subpacket.cpp
  openpgp/signature/subpacket/preferred_compression_algorithms_subpacket.cpp
  openpgp/signature/subpacket/preferred_hash_algorithms_subpacket.cpp
  openpgp/signature/subpacket/preferred_key_server_subpacket.cpp
  openpgp/signature/subpacket/preferred_symmetric_algorithms_subpacket.cpp
  openpgp/signature/subpacket/primary_user_id_subpacket.cpp
  openpgp/signature/subpacket/raw_signature_subpacket.cpp
  openpgp/signature/subpacket/reason_for_revocation_subpacket.cpp
  openpgp/signature/subpacket/regular_expression_subpacket.cpp
  openpgp/signature/subpacket/revocable_subpacket.cpp
  openpgp/signature/subpacket/revocation_key_subpacket.cpp
  openpgp/signature/subpacket/signature_creation_time_subpacket.cpp
  openpgp/signature/subpacket/signature_expiration_time_subpacket.cpp
  openpgp/signature/subpacket/signature_target_subpacket.cpp
  openpgp/signature/subpacket/signers_user_id_subpacket.cpp
  openpgp/signature/subpacket/trust_signature_subpacket.cpp
  openpgp/symmetrically_encrypted_data_packet.cpp
  openpgp/symmetrically_encrypted_integrity_protected_data_packet.cpp
  openpgp/trust_packet.cpp
  openpgp/user_attribute/subpacket/image_attribute_subpacket.cpp
  openpgp/user_attribute/subpacket/raw_user_attribute_subpacket.cpp
  openpgp/user_attribute/user_attribute_subpacket.cpp
  openpgp/user_attribute_packet.cpp
  openpgp/user_id_packet.cpp
  parser/openpgp.cpp
  parser/parser_input.cpp
  proto/http.cpp
  proto/uri.cpp
  utils/stream.cpp
  utils/time.cpp
)
target_include_directories(neopg PUBLIC
  $<INSTALL_INTERFACE:include>
  $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}>
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<BUILD_INTERFACE:${PEGTL_ROOT}/include>
  $<BUILD_INTERFACE:${JSON_ROOT}/include>
  $<BUILD_INTERFACE:${CURL_INCLUDE_DIRS}>
)


target_compile_options(neopg
  PRIVATE
  -fvisibility=hidden
)

target_link_libraries(neopg PUBLIC
  PkgConfig::botan-2
  ${CURL_LDFLAGS} ${CURL_LIBRARIES}
)

add_library(neopg::neopg ALIAS neopg)

install(DIRECTORY ${CMAKE_SOURCE_DIR}/neopg/crypto
  DESTINATION include/neopg
  FILES_MATCHING PATTERN *.h
)

install(DIRECTORY ${CMAKE_SOURCE_DIR}/neopg/openpgp
  DESTINATION include/neopg
  FILES_MATCHING PATTERN *.h
)

install(DIRECTORY ${CMAKE_SOURCE_DIR}/neopg/parser
  DESTINATION include/neopg
  FILES_MATCHING PATTERN *.h
)

install(DIRECTORY ${CMAKE_SOURCE_DIR}/neopg/proto
  DESTINATION include/neopg
  FILES_MATCHING PATTERN *.h
)

install(DIRECTORY ${CMAKE_SOURCE_DIR}/neopg/utils
  DESTINATION include/neopg
  FILES_MATCHING PATTERN *.h
)

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}>/include/
  DESTINATION include
  FILES_MATCHING PATTERN *.h
)

install(TARGETS neopg
  EXPORT neopg
  LIBRARY
    DESTINATION lib
  ARCHIVE
    DESTINATION lib
  PUBLIC_HEADER
    DESTINATION include
)


add_subdirectory(tests)
