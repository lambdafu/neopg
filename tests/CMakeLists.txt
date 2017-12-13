# NeoPG - tests
#   Copyright 2017 The NeoPG developers
#
# NeoPG is released under the Simplified BSD License (see license.txt)

add_executable(test-neopg
  openpgp/header.cpp
  openpgp/marker_packet.cpp
  openpgp/literal_data_packet.cpp
  openpgp/user_id_packet.cpp
  openpgp/user_attribute_packet.cpp
  openpgp/modification_detection_code_packet.cpp
  openpgp/symmetrically_encrypted_integrity_protected_data_packet.cpp
  openpgp/symmetrically_encrypted_data_packet.cpp
  openpgp/compressed_data_packet.cpp
  openpgp/trust_packet.cpp
  utils/stream.cpp
  parser/openpgp.cpp
  proto/uri.cpp
  proto/http.cpp
)

target_compile_options(test-neopg
  PRIVATE
  -std=c++11
  -U_GNU_SOURCE -D_POSIX_SOURCE=1 -D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=700
)

target_link_libraries(test-neopg
  PRIVATE
  libneopg
  GTest::GTest GTest::Main
)

add_test(NeoPGTest test-neopg
  COMMAND test-neopg test_xml_output --gtest_output=xml:test-neopg.xml
)
