// OpenPGP signature data (implementation)
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/signature/signature_data.h>

#include <neopg/openpgp/signature/data/v3_signature_data.h>
#include <neopg/openpgp/signature/data/v4_signature_data.h>

#include <memory>

using namespace NeoPG;

std::unique_ptr<SignatureData> SignatureData::create_or_throw(
    SignatureVersion version, ParserInput& in) {
  std::unique_ptr<SignatureData> signature;

  switch (version) {
    case SignatureVersion::V2:
    case SignatureVersion::V3:
      signature = V3SignatureData::create_or_throw(in);
      break;
    case SignatureVersion::V4:
      signature = V4SignatureData::create_or_throw(in);
      break;
    default:
      in.error("unknown signature version");
  }

  return signature;
}
