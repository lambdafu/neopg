// OpenPGP signature data (tests)
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/signature/signature_data.h>

#include <neopg/openpgp/signature/data/v3_signature_data.h>
#include <neopg/openpgp/signature/data/v4_signature_data.h>

#include <gtest/gtest.h>

#include <array>
#include <memory>
#include <sstream>

using namespace NeoPG;

TEST(OpenpgpSignatureData, CreateV3) {
  // Test V3 packets.
  const std::string raw{
      "\x05\x10\x12\x34\x56\x78"
      "\xab\xcd\xef\xab\xcd\xef\xab\xcd"
      "\x01"
      "\x02"
      "\x67\x89"
      "\x00\x11\x01\x42\x23",
      23};
  ParserInput in(raw.data(), raw.length());
  auto signature = SignatureData::create_or_throw(SignatureVersion::V3, in);
  ASSERT_EQ(signature->version(), SignatureVersion::V3);
  auto v3sig = dynamic_cast<V3SignatureData*>(signature.get());
  ASSERT_NE(v3sig, nullptr);
}
