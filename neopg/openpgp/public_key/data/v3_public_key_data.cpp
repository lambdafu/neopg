// OpenPGP public key packet data v3 (implementation)
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/public_key/data/v3_public_key_data.h>

#include <neopg/openpgp/public_key/material/rsa_public_key_material.h>

#include <neopg/intern/cplusplus.h>
#include <neopg/intern/pegtl.h>

#include <botan/md5.h>

using namespace NeoPG;

namespace NeoPG {
namespace v3_public_key_data {

using namespace pegtl;

// Grammar
struct created : uint32_be::any {};
struct days_valid : uint16_be::any {};
struct algorithm
    : uint8::one<static_cast<uint8_t>(PublicKeyAlgorithm::Rsa),
                 static_cast<uint8_t>(PublicKeyAlgorithm::RsaEncrypt),
                 static_cast<uint8_t>(PublicKeyAlgorithm::RsaSign)> {};
struct grammar : must<created, days_valid, algorithm> {};

// Action
template <typename Rule>
struct action : nothing<Rule> {};

template <>
struct action<created>
    : bind<V3PublicKeyData, uint32_t, &V3PublicKeyData::m_created> {};

template <>
struct action<days_valid>
    : bind<V3PublicKeyData, uint16_t, &V3PublicKeyData::m_days_valid> {};

template <>
struct action<algorithm>
    : bind<V3PublicKeyData, PublicKeyAlgorithm, &V3PublicKeyData::m_algorithm> {
};

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
const std::string control<created>::error_message =
    "v3 public key data is missing created time";

template <>
const std::string control<days_valid>::error_message =
    "v3 public key data is missing days invalid";

template <>
const std::string control<algorithm>::error_message =
    "v3 public key data has invalid algorithm specifier";
}  // namespace v3_public_key_data

std::unique_ptr<V3PublicKeyData> V3PublicKeyData::create_or_throw(
    ParserInput& in) {
  auto packet = make_unique<V3PublicKeyData>();

  pegtl::parse<v3_public_key_data::grammar, v3_public_key_data::action,
               v3_public_key_data::control>(in.m_impl->m_input, *packet.get());
  packet->m_key = PublicKeyMaterial::create_or_throw(packet->m_algorithm, in);

  return packet;
}

void V3PublicKeyData::write(std::ostream& out) const {
  out << static_cast<uint8_t>(m_created >> 24)
      << static_cast<uint8_t>(m_created >> 16)
      << static_cast<uint8_t>(m_created >> 8)
      << static_cast<uint8_t>(m_created);
  out << static_cast<uint8_t>(m_days_valid >> 8)
      << static_cast<uint8_t>(m_days_valid);
  out << static_cast<uint8_t>(m_algorithm);
  if (m_key) m_key->write(out);
}

std::vector<uint8_t> V3PublicKeyData::fingerprint() const {
  Botan::MD5 md5;
  auto rsa = dynamic_cast<RsaPublicKeyMaterial*>(m_key.get());
  if (rsa) {
    md5.update(rsa->m_n.bits());
    md5.update(rsa->m_e.bits());
  }
  return md5.final_stdvec();
}

std::vector<uint8_t> V3PublicKeyData::keyid() const {
  std::vector<uint8_t> keyid(KEYID_LENGTH, static_cast<uint8_t>(0x00));
  auto rsa = dynamic_cast<RsaPublicKeyMaterial*>(m_key.get());
  if (rsa) {
    const std::vector<uint8_t>& n = rsa->m_n.bits();
    size_t len = std::min(keyid.size(), n.size());
    std::copy_backward(n.end() - len, n.end(), keyid.end());
  }
  return keyid;
}

}  // namespace NeoPG
