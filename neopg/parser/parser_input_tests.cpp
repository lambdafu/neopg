// OpenPGP parser
// Copyright 2017-2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/parser/parser_input.h>

#include "gtest/gtest.h"

using namespace NeoPG;

TEST(NeopgTest, parser_input_test) {
  auto str = std::string{"foobar"};
  ParserInput in(str.data(), str.length());
  ASSERT_EQ(in.size(), str.length());
  ASSERT_EQ(in.position(), 0);
  ASSERT_ANY_THROW(in.error("test error"));
  ASSERT_EQ(str, in.current());

  const std::size_t off = 3;
  in.bump(off);
  ASSERT_EQ(in.position(), off);
  ASSERT_EQ(str.data() + off, in.current());

  const auto vec = std::vector<uint8_t>{0x10, 0x20, 0x30, 0x40};
  ParserInput in_vec{vec.data(), vec.size()};
  ASSERT_EQ(in_vec.size(), 4);
}
