// OpenPGP rsa signature material (implementation)
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/signature/material/rsa_signature_material.h>

#include <neopg/intern/cplusplus.h>

using namespace NeoPG;

std::unique_ptr<RsaSignatureMaterial> RsaSignatureMaterial::create_or_throw(
    ParserInput& in) {
  auto data = make_unique<RsaSignatureMaterial>();
  data->m_m_pow_d.parse(in);
  return data;
}

void RsaSignatureMaterial::write(std::ostream& out) const {
  m_m_pow_d.write(out);
}
