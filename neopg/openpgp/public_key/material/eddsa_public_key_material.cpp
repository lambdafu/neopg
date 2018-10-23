// OpenPGP EDDSA public key material (implementation)
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/public_key/material/eddsa_public_key_material.h>

#include <neopg/intern/cplusplus.h>
#include <neopg/intern/pegtl.h>

using namespace NeoPG;

std::unique_ptr<EddsaPublicKeyMaterial> EddsaPublicKeyMaterial::create_or_throw(
    ParserInput& in) {
  auto data = make_unique<EddsaPublicKeyMaterial>();
  data->m_curve.parse(in);
  data->m_key.parse(in);

  return data;
}

void EddsaPublicKeyMaterial::write(std::ostream& out) const {
  m_curve.write(out);
  m_key.write(out);
}
