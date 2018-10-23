// OpenPGP v4 signature data (implementation)
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/signature/data/v4_signature_data.h>

#include <neopg/intern/cplusplus.h>
#include <neopg/intern/pegtl.h>

#include <algorithm>
#include <iterator>

using namespace NeoPG;

namespace NeoPG {
namespace v4_signature_data {

using namespace pegtl;

// Grammar
struct type : any {};
struct public_key_algorithm : any {};
struct hash_algorithm : any {};
struct grammar : must<type, public_key_algorithm, hash_algorithm> {};

struct quick : bytes<2> {};
struct tail : must<quick> {};

// Action
template <typename Rule>
struct action : nothing<Rule> {};

template <>
struct action<type>
    : bind<V4SignatureData, SignatureType, &V4SignatureData::m_type> {};

template <>
struct action<public_key_algorithm>
    : bind<V4SignatureData, PublicKeyAlgorithm,
           &V4SignatureData::m_public_key_algorithm> {};

template <>
struct action<hash_algorithm>
    : bind<V4SignatureData, HashAlgorithm, &V4SignatureData::m_hash_algorithm> {
};

template <>
struct action<quick> {
  template <typename Input>
  static void apply(const Input& in, V4SignatureData& data) {
    auto begin = reinterpret_cast<const uint8_t*>(in.begin());
    std::copy_n(begin, in.size(), std::begin(data.m_quick));
  }
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
const std::string control<type>::error_message =
    "v4 signature data is missing type";

template <>
const std::string control<quick>::error_message =
    "v4 signature data is missing quick check data";

template <>
const std::string control<public_key_algorithm>::error_message =
    "v4 signature data is missing or has invalid public key algorithm";

template <>
const std::string control<hash_algorithm>::error_message =
    "v4 signature data is missing hash algorithm";

}  // namespace v4_signature_data
}  // namespace NeoPG

std::unique_ptr<V4SignatureData> V4SignatureData::create_or_throw(
    ParserInput& in) {
  auto packet = make_unique<V4SignatureData>();
  pegtl::parse<v4_signature_data::grammar, v4_signature_data::action,
               v4_signature_data::control>(in.m_impl->m_input, *packet);
  packet->m_hashed_subpackets = V4SignatureSubpacketData::create_or_throw(in);
  packet->m_unhashed_subpackets = V4SignatureSubpacketData::create_or_throw(in);
  pegtl::parse<v4_signature_data::tail, v4_signature_data::action,
               v4_signature_data::control>(in.m_impl->m_input, *packet);
  packet->m_signature =
      SignatureMaterial::create_or_throw(packet->m_public_key_algorithm, in);
  return packet;
}

void V4SignatureData::write(std::ostream& out) const {
  out << static_cast<uint8_t>(m_type);
  out << static_cast<uint8_t>(m_public_key_algorithm);
  out << static_cast<uint8_t>(m_hash_algorithm);
  m_hashed_subpackets->write(out);
  m_unhashed_subpackets->write(out);
  out.write(reinterpret_cast<const char*>(m_quick.data()), m_quick.size());
  if (m_signature) m_signature->write(out);
}
