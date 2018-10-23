// OpenPGP public key material (implementation)
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/public_key/public_key_material.h>

#include <neopg/openpgp/public_key/material/dsa_public_key_material.h>
#include <neopg/openpgp/public_key/material/ecdh_public_key_material.h>
#include <neopg/openpgp/public_key/material/ecdsa_public_key_material.h>
#include <neopg/openpgp/public_key/material/eddsa_public_key_material.h>
#include <neopg/openpgp/public_key/material/elgamal_public_key_material.h>
#include <neopg/openpgp/public_key/material/raw_public_key_material.h>
#include <neopg/openpgp/public_key/material/rsa_public_key_material.h>

#include <neopg/intern/cplusplus.h>
#include <neopg/intern/pegtl.h>

using namespace NeoPG;

std::unique_ptr<PublicKeyMaterial> PublicKeyMaterial::create_or_throw(
    PublicKeyAlgorithm algorithm, ParserInput& in) {
  switch (algorithm) {
    case PublicKeyAlgorithm::Rsa:
    case PublicKeyAlgorithm::RsaEncrypt:
    case PublicKeyAlgorithm::RsaSign:
      return RsaPublicKeyMaterial::create_or_throw(in);
    case PublicKeyAlgorithm::Dsa:
      return DsaPublicKeyMaterial::create_or_throw(in);
    case PublicKeyAlgorithm::Elgamal:
    case PublicKeyAlgorithm::ElgamalEncrypt:
      return ElgamalPublicKeyMaterial::create_or_throw(in);
    case PublicKeyAlgorithm::Ecdsa:
      return EcdsaPublicKeyMaterial::create_or_throw(in);
    case PublicKeyAlgorithm::Ecdh:
      return EcdhPublicKeyMaterial::create_or_throw(in);
    case PublicKeyAlgorithm::Eddsa:
      return EddsaPublicKeyMaterial::create_or_throw(in);
    default:
      return RawPublicKeyMaterial::create_or_throw(algorithm, in);
  }
  // Never reached.
  return nullptr;
}
