// OpenPGP reason for revocation subpacket (tests)
// Copyright 2017-2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/signature/subpacket/reason_for_revocation_subpacket.h>

#include "gtest/gtest.h"

#include <memory>
#include <sstream>

using namespace NeoPG;

TEST(OpenpgpReasonForRevocationSubpacket, Create) {
  {
    std::stringstream out;
    ReasonForRevocationSubpacket packet;
    packet.m_code = RevocationCode::KeyCompromised;
    packet.m_reason = "compromised";
    packet.write(out);
    ASSERT_EQ(out.str(), std::string("\x0d\x1d\x02"
                                     "compromised",
                                     14));
  }
}

TEST(OpenpgpReasonForRevocationSubpacket, ParseBad) {
  // Test parser (packet too long)
  const auto packet =
      std::vector<uint8_t>(ReasonForRevocationSubpacket::MAX_LENGTH + 2, 0xff);
  ParserInput in{(const char*)packet.data(), packet.size()};

  ASSERT_ANY_THROW(ReasonForRevocationSubpacket::create_or_throw(in));
  ASSERT_EQ(in.position(),
            (uint32_t)ReasonForRevocationSubpacket::MAX_LENGTH + 1);
}
