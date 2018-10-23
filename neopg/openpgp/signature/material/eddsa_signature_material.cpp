// OpenPGP eddsa signature material (implementation)
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/signature/material/eddsa_signature_material.h>

#include <neopg/intern/cplusplus.h>

using namespace NeoPG;

std::unique_ptr<EddsaSignatureMaterial> EddsaSignatureMaterial::create_or_throw(
    ParserInput& in) {
  auto data = make_unique<EddsaSignatureMaterial>();
  data->m_r.parse(in);
  data->m_s.parse(in);
  return data;
}

void EddsaSignatureMaterial::write(std::ostream& out) const {
  m_r.write(out);
  m_s.write(out);
}
