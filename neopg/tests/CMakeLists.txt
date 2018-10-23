# NeoPG - tests
# Copyright 2017 The NeoPG developers
#
# NeoPG is released under the Simplified BSD License (see license.txt)

add_executable(test-libneopg
  # Pure unit tests are located alongside the implementation.
  ../openpgp/compressed_data_packet_tests.cpp
  ../openpgp/literal_data_packet_tests.cpp
  ../openpgp/marker_packet_tests.cpp
  ../openpgp/modification_detection_code_packet_tests.cpp
  ../openpgp/multiprecision_integer_tests.cpp
  ../openpgp/object_identifier_tests.cpp
  ../openpgp/packet_header_tests.cpp
  ../openpgp/public_key_packet_tests.cpp
  ../openpgp/public_key/data/v3_public_key_data_tests.cpp
  ../openpgp/public_key/data/v4_public_key_data_tests.cpp
  ../openpgp/public_key/material/dsa_public_key_material_tests.cpp
  ../openpgp/public_key/material/ecdh_public_key_material_tests.cpp
  ../openpgp/public_key/material/ecdsa_public_key_material_tests.cpp
  ../openpgp/public_key/material/eddsa_public_key_material_tests.cpp
  ../openpgp/public_key/material/elgamal_public_key_material_tests.cpp
  ../openpgp/public_key/material/raw_public_key_material_tests.cpp
  ../openpgp/public_key/material/rsa_public_key_material_tests.cpp
  ../openpgp/public_key/public_key_data_tests.cpp
  ../openpgp/public_key/public_key_material_tests.cpp
  ../openpgp/public_subkey_packet_tests.cpp
  ../openpgp/signature_packet_tests.cpp
  ../openpgp/signature/signature_data_tests.cpp
  ../openpgp/signature/data/v3_signature_data_tests.cpp
  ../openpgp/signature/data/v4_signature_data_tests.cpp
  ../openpgp/signature/data/v4_signature_subpacket_data_tests.cpp
  ../openpgp/signature/material/raw_signature_material_tests.cpp
  ../openpgp/signature/material/rsa_signature_material_tests.cpp
  ../openpgp/signature/material/dsa_signature_material_tests.cpp
  ../openpgp/signature/material/ecdsa_signature_material_tests.cpp
  ../openpgp/signature/material/eddsa_signature_material_tests.cpp
  ../openpgp/signature/signature_material_tests.cpp
  ../openpgp/signature/signature_subpacket_tests.cpp
  ../openpgp/signature/subpacket/embedded_signature_subpacket_tests.cpp
  ../openpgp/signature/subpacket/exportable_certification_subpacket_tests.cpp
  ../openpgp/signature/subpacket/features_subpacket_tests.cpp
  ../openpgp/signature/subpacket/issuer_subpacket_tests.cpp
  ../openpgp/signature/subpacket/key_expiration_time_subpacket_tests.cpp
  ../openpgp/signature/subpacket/key_flags_subpacket_tests.cpp
  ../openpgp/signature/subpacket/key_server_preferences_subpacket_tests.cpp
  ../openpgp/signature/subpacket/notation_data_subpacket_tests.cpp
  ../openpgp/signature/subpacket/policy_uri_subpacket_tests.cpp
  ../openpgp/signature/subpacket/preferred_compression_algorithms_subpacket_tests.cpp
  ../openpgp/signature/subpacket/preferred_hash_algorithms_subpacket_tests.cpp
  ../openpgp/signature/subpacket/preferred_key_server_subpacket_tests.cpp
  ../openpgp/signature/subpacket/preferred_symmetric_algorithms_subpacket_tests.cpp
  ../openpgp/signature/subpacket/primary_user_id_subpacket_tests.cpp
  ../openpgp/signature/subpacket/raw_signature_subpacket_tests.cpp
  ../openpgp/signature/subpacket/reason_for_revocation_subpacket_tests.cpp
  ../openpgp/signature/subpacket/regular_expression_subpacket_tests.cpp
  ../openpgp/signature/subpacket/revocable_subpacket_tests.cpp
  ../openpgp/signature/subpacket/revocation_key_subpacket_tests.cpp
  ../openpgp/signature/subpacket/signature_creation_time_subpacket_tests.cpp
  ../openpgp/signature/subpacket/signature_expiration_time_subpacket_tests.cpp
  ../openpgp/signature/subpacket/signature_target_subpacket_tests.cpp
  ../openpgp/signature/subpacket/signers_user_id_subpacket_tests.cpp
  ../openpgp/signature/subpacket/trust_signature_subpacket_tests.cpp
  ../openpgp/symmetrically_encrypted_data_packet_tests.cpp
  ../openpgp/symmetrically_encrypted_integrity_protected_data_packet_tests.cpp
  ../openpgp/trust_packet_tests.cpp
  ../openpgp/user_attribute/subpacket/image_attribute_subpacket_tests.cpp
  ../openpgp/user_attribute/subpacket/raw_user_attribute_subpacket_tests.cpp
  ../openpgp/user_attribute/user_attribute_subpacket_tests.cpp
  ../openpgp/user_attribute_packet_tests.cpp
  ../openpgp/user_id_packet_tests.cpp
  ../parser/openpgp_tests.cpp
  ../parser/parser_input_tests.cpp
  ../proto/http_tests.cpp
  ../proto/uri_tests.cpp
  ../utils/stream_tests.cpp
)

target_link_libraries(test-libneopg
  PRIVATE
  neopg::neopg
  GTest::GTest
  GTest::Main
)

add_test(NeopgTest test-libneopg
  COMMAND test-libneopg test_xml_output --gtest_output=xml:test-libneopg.xml
)
add_dependencies(tests test-libneopg)
