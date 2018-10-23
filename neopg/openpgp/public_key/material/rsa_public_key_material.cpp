// OpenPGP RSA public key material (implementation)
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/public_key/material/rsa_public_key_material.h>

#include <neopg/intern/cplusplus.h>
#include <neopg/intern/pegtl.h>

using namespace NeoPG;

std::unique_ptr<RsaPublicKeyMaterial> RsaPublicKeyMaterial::create_or_throw(
    ParserInput& in) {
  auto data = make_unique<RsaPublicKeyMaterial>();
  data->m_n.parse(in);
  data->m_e.parse(in);
  return data;
}

void RsaPublicKeyMaterial::write(std::ostream& out) const {
  m_n.write(out);
  m_e.write(out);
}
