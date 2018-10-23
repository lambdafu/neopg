// OpenPGP v3 signature data (implementation)
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/signature/data/v3_signature_data.h>

#include <neopg/intern/cplusplus.h>
#include <neopg/intern/pegtl.h>

#include <algorithm>
#include <iterator>

using namespace NeoPG;

namespace NeoPG {
namespace v3_signature_data {

using namespace pegtl;

// Grammar
struct type : any {};
struct created : bytes<4> {};
struct v3_hashed : seq<one<0x05>, must<type, created>> {};

struct signer : bytes<8> {};
struct quick : bytes<2> {};
struct public_key_algorithm
    : uint8::one<static_cast<uint8_t>(PublicKeyAlgorithm::Rsa),
                 static_cast<uint8_t>(PublicKeyAlgorithm::RsaEncrypt),
                 static_cast<uint8_t>(PublicKeyAlgorithm::RsaSign),
                 static_cast<uint8_t>(PublicKeyAlgorithm::Dsa)> {};
struct hash_algorithm : any {};

struct grammar
    : must<v3_hashed, signer, public_key_algorithm, hash_algorithm, quick> {};

// Action
template <typename Rule>
struct action : nothing<Rule> {};

template <>
struct action<type>
    : bind<V3SignatureData, SignatureType, &V3SignatureData::m_type> {};

template <>
struct action<created>
    : bind<V3SignatureData, uint32_t, &V3SignatureData::m_created> {};

template <>
struct action<signer> {
  template <typename Input>
  static void apply(const Input& in, V3SignatureData& pkt) {
    auto begin = reinterpret_cast<const uint8_t*>(in.begin());
    std::copy_n(begin, in.size(), std::begin(pkt.m_signer));
  }
};

template <>
struct action<public_key_algorithm>
    : bind<V3SignatureData, PublicKeyAlgorithm,
           &V3SignatureData::m_public_key_algorithm> {};

template <>
struct action<hash_algorithm>
    : bind<V3SignatureData, HashAlgorithm, &V3SignatureData::m_hash_algorithm> {
};

template <>
struct action<quick> {
  template <typename Input>
  static void apply(const Input& in, V3SignatureData& pkt) {
    auto begin = reinterpret_cast<const uint8_t*>(in.begin());
    std::copy_n(begin, in.size(), std::begin(pkt.m_quick));
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
    "v3 signature data is missing type";

template <>
const std::string control<created>::error_message =
    "v3 signature data is missing created time";

template <>
const std::string control<v3_hashed>::error_message =
    "v3 signature data is missing hashed data";

template <>
const std::string control<signer>::error_message =
    "v3 signature data is missing signer";

template <>
const std::string control<public_key_algorithm>::error_message =
    "v3 signature data is missing or has invalid public key algorithm";

template <>
const std::string control<hash_algorithm>::error_message =
    "v3 signature data is missing hash algorithm";

template <>
const std::string control<quick>::error_message =
    "v3 signature data is missing quick check data";

}  // namespace v3_signature_data
}  // namespace NeoPG

std::unique_ptr<V3SignatureData> V3SignatureData::create_or_throw(
    ParserInput& in) {
  auto packet = make_unique<V3SignatureData>();

  pegtl::parse<v3_signature_data::grammar, v3_signature_data::action,
               v3_signature_data::control>(in.m_impl->m_input, *packet);
  packet->m_signature =
      SignatureMaterial::create_or_throw(packet->m_public_key_algorithm, in);

  return packet;
}

void V3SignatureData::write(std::ostream& out) const {
  out << static_cast<uint8_t>(0x05);
  out << static_cast<uint8_t>(m_type);
  out << static_cast<uint8_t>(m_created >> 24)
      << static_cast<uint8_t>(m_created >> 16)
      << static_cast<uint8_t>(m_created >> 8)
      << static_cast<uint8_t>(m_created);
  out.write(reinterpret_cast<const char*>(m_signer.data()), m_signer.size());
  out << static_cast<uint8_t>(m_public_key_algorithm);
  out << static_cast<uint8_t>(m_hash_algorithm);
  out.write(reinterpret_cast<const char*>(m_quick.data()), m_quick.size());
  if (m_signature) m_signature->write(out);
}
