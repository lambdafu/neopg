// OpenPGP exportable certification subpacket (tests)
// Copyright 2017-2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/signature/subpacket/exportable_certification_subpacket.h>

#include "gtest/gtest.h"

#include <memory>
#include <sstream>

using namespace NeoPG;

TEST(OpenpgpExportableCertificationSubpacket, Create) {
  {
    std::stringstream out;
    ExportableCertificationSubpacket packet;
    packet.m_exportable = 0x01;
    packet.write(out);
    ASSERT_EQ(out.str(), std::string("\x02\x04\x01", 3));
  }
}

TEST(OpenpgpExportableCertificationSubpacket, ParseShort) {
  // Test parser (packet too long)
  ParserInput in{""};

  ASSERT_ANY_THROW(ExportableCertificationSubpacket::create_or_throw(in));
  ASSERT_EQ(in.position(), 0);
}

TEST(OpenpgpExportableCertificationSubpacket, ParseLong) {
  // Test parser (packet too long)
  const auto packet = std::vector<uint8_t>(3, 0xff);
  ParserInput in{(const char*)packet.data(), packet.size()};

  ASSERT_ANY_THROW(ExportableCertificationSubpacket::create_or_throw(in));
  ASSERT_EQ(in.position(), 1);
}
