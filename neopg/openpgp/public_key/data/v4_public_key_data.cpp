// OpenPGP v4 public key packet data (implementation)
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/public_key/data/v4_public_key_data.h>

#include <neopg/intern/cplusplus.h>
#include <neopg/intern/pegtl.h>

#include <botan/sha160.h>

using namespace NeoPG;

namespace NeoPG {
namespace v4_public_key_data {

using namespace pegtl;

// Grammar
struct created : bytes<4> {};
struct algorithm : any {};
struct grammar : must<created, algorithm> {};

// Action
template <typename Rule>
struct action : nothing<Rule> {};

template <>
struct action<created>
    : bind<V4PublicKeyData, uint32_t, &V4PublicKeyData::m_created> {};

template <>
struct action<algorithm>
    : bind<V4PublicKeyData, PublicKeyAlgorithm, &V4PublicKeyData::m_algorithm> {
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
    "v4 public key data is missing created time";

template <>
const std::string control<algorithm>::error_message =
    "v4 public key data is missing algorithm specifier";

}  // namespace v4_public_key_data
}  // namespace NeoPG

std::unique_ptr<V4PublicKeyData> V4PublicKeyData::create_or_throw(
    ParserInput& in) {
  auto packet = make_unique<V4PublicKeyData>();

  pegtl::parse<v4_public_key_data::grammar, v4_public_key_data::action,
               v4_public_key_data::control>(in.m_impl->m_input, *packet.get());
  packet->m_key = PublicKeyMaterial::create_or_throw(packet->m_algorithm, in);
  // We accept all algorithms that are known to PublicKeyMaterial.

  return packet;
}

void V4PublicKeyData::write(std::ostream& out) const {
  out << static_cast<uint8_t>(m_created >> 24)
      << static_cast<uint8_t>(m_created >> 16)
      << static_cast<uint8_t>(m_created >> 8)
      << static_cast<uint8_t>(m_created);
  out << static_cast<uint8_t>(m_algorithm);
  if (m_key) m_key->write(out);
}

std::vector<uint8_t> V4PublicKeyData::fingerprint() const {
  std::stringstream out;
  out << static_cast<uint8_t>(version());
  write(out);
  auto public_key = out.str();

  Botan::SHA_160 sha1;
  sha1.update(0x99);
  // The length may be truncated.
  auto length = static_cast<uint16_t>(public_key.size());
  sha1.update_be(length);
  sha1.update(public_key);

  return sha1.final_stdvec();
}

std::vector<uint8_t> V4PublicKeyData::keyid() const {
  auto fpr = fingerprint();
  return std::vector<uint8_t>(fpr.begin() + 12, fpr.end());
}
