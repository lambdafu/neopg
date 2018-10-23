// OpenPGP signature material (implementation)
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/signature/signature_material.h>

#include <neopg/openpgp/signature/material/dsa_signature_material.h>
#include <neopg/openpgp/signature/material/ecdsa_signature_material.h>
#include <neopg/openpgp/signature/material/eddsa_signature_material.h>
#include <neopg/openpgp/signature/material/raw_signature_material.h>
#include <neopg/openpgp/signature/material/rsa_signature_material.h>

#include <neopg/intern/cplusplus.h>

using namespace NeoPG;

std::unique_ptr<SignatureMaterial> SignatureMaterial::create_or_throw(
    PublicKeyAlgorithm algorithm, ParserInput& in) {
  switch (algorithm) {
    case PublicKeyAlgorithm::Rsa:
    case PublicKeyAlgorithm::RsaSign:  // For example SKS 9BA6EDF38749875
      return RsaSignatureMaterial::create_or_throw(in);
    case PublicKeyAlgorithm::Dsa:
      return DsaSignatureMaterial::create_or_throw(in);
    case PublicKeyAlgorithm::Ecdsa:
      return EcdsaSignatureMaterial::create_or_throw(in);
    case PublicKeyAlgorithm::Eddsa:
      return EddsaSignatureMaterial::create_or_throw(in);
    default:
      return RawSignatureMaterial::create_or_throw(algorithm, in);
  }
  // Never reached.
  return nullptr;
}
