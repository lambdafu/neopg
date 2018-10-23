# NeoPG - tests
# Copyright 2017 The NeoPG developers
#
# NeoPG is released under the Simplified BSD License (see license.txt)

add_executable(test-neopg
  # Pure unit tests are located alongside the implementation.
  ../io/streams_tests.cpp
)

target_link_libraries(test-neopg
  PRIVATE
  neopg
  neopg-tool
  GTest::GTest GTest::Main
)

add_test(NeopgToolTest test-neopg
  COMMAND test-neopg test_xml_output --gtest_output=xml:test-neopg.xml
)
add_dependencies(tests test-neopg)
