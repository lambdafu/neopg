// OpenPGP public key packet data (implementation)
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/public_key/public_key_data.h>

#include <neopg/openpgp/public_key/data/v3_public_key_data.h>
#include <neopg/openpgp/public_key/data/v4_public_key_data.h>

#include <neopg/intern/cplusplus.h>
#include <neopg/intern/pegtl.h>

#include <assert.h>

using namespace NeoPG;

std::unique_ptr<PublicKeyData> PublicKeyData::create_or_throw(
    PublicKeyVersion version, ParserInput& in) {
  std::unique_ptr<PublicKeyData> public_key;

  switch (version) {
    case PublicKeyVersion::V2:
    case PublicKeyVersion::V3:
      public_key = V3PublicKeyData::create_or_throw(in);
      break;
    case PublicKeyVersion::V4:
      public_key = V4PublicKeyData::create_or_throw(in);
      break;
    default:
      in.error("unknown public key version");
  }

  return public_key;
}
