// OpenPGP ECDH public key material (implementation)
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/public_key/material/ecdh_public_key_material.h>

#include <neopg/intern/cplusplus.h>
#include <neopg/intern/pegtl.h>

using namespace NeoPG;

namespace NeoPG {
namespace ecdh_public_key_material {

using namespace pegtl;

// Grammar
struct header_size : one<(char)0x03> {};
struct header_reserved : one<(char)0x01> {};
struct hash_algo : any {};
struct symmetric_algo : any {};
struct ecdh_kdf
    : must<header_size, header_reserved, hash_algo, symmetric_algo> {};

// Action
template <typename Rule>
struct action : nothing<Rule> {};

template <>
struct action<hash_algo>
    : bind<EcdhPublicKeyMaterial, uint8_t, &EcdhPublicKeyMaterial::m_hash> {};

template <>
struct action<symmetric_algo>
    : bind<EcdhPublicKeyMaterial, uint8_t, &EcdhPublicKeyMaterial::m_sym> {};

// Control
template <typename Rule>
struct control : pegtl::normal<Rule> {
  static const std::string error_message;

  template <typename Input, typename... States>
  static void raise(const Input& in, States&&...) {
    throw parser_error(error_message, in);
  }
};

template <>
const std::string control<header_size>::error_message =
    "ecdh public key material has invalid header size";

template <>
const std::string control<header_reserved>::error_message =
    "ecdh public key material has invalid header reserved octet";

template <>
const std::string control<hash_algo>::error_message =
    "ecdh public key material is missing hash algorithm";

template <>
const std::string control<symmetric_algo>::error_message =
    "ecdh public key material is missing symmetric algorithm";

template <>
const std::string control<eof>::error_message =
    "ecdh public key material has trailing data";

}  // namespace ecdh_public_key_material
}  // namespace NeoPG

using namespace NeoPG;

std::unique_ptr<EcdhPublicKeyMaterial> EcdhPublicKeyMaterial::create_or_throw(
    ParserInput& in) {
  auto data = make_unique<EcdhPublicKeyMaterial>();
  data->m_curve.parse(in);
  data->m_key.parse(in);
  pegtl::parse<ecdh_public_key_material::ecdh_kdf,
               ecdh_public_key_material::action,
               ecdh_public_key_material::control>(in.m_impl->m_input, *data);
  return data;
}

void EcdhPublicKeyMaterial::write(std::ostream& out) const {
  m_curve.write(out);
  m_key.write(out);
  out << static_cast<uint8_t>(0x03) << static_cast<uint8_t>(0x01)
      << static_cast<uint8_t>(m_hash) << static_cast<uint8_t>(m_sym);
}
