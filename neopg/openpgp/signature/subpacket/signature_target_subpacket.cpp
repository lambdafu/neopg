// OpenPGP signature target subpacket (implementation)
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/signature/subpacket/signature_target_subpacket.h>

#include <neopg/parser/parser_input.h>
#include <neopg/utils/stream.h>

#include <neopg/intern/cplusplus.h>
#include <neopg/intern/pegtl.h>

#include <botan/md5.h>
#include <botan/rmd160.h>
#include <botan/sha160.h>
#include <botan/sha2_32.h>
#include <botan/sha2_64.h>

using namespace NeoPG;

namespace NeoPG {
namespace signature_target_subpacket {

using namespace pegtl;

// Grammar
struct pubkey_algo : any {};
struct hash_algo : any {};
// We don't know the size of future or private hash algorithms.
struct hash : rep_max_any<SignatureTargetSubpacket::MAX_LENGTH> {};
struct grammar : must<pubkey_algo, hash_algo, hash, eof> {};

// Action
template <typename Rule>
struct action : nothing<Rule> {};

template <>
struct action<pubkey_algo>
    : bind<SignatureTargetSubpacket, PublicKeyAlgorithm,
           &SignatureTargetSubpacket::m_public_key_algorithm> {};

template <>
struct action<hash_algo> : bind<SignatureTargetSubpacket, HashAlgorithm,
                                &SignatureTargetSubpacket::m_hash_algorithm> {};

template <>
struct action<hash> : bind<SignatureTargetSubpacket, std::vector<uint8_t>,
                           &SignatureTargetSubpacket::m_hash> {};

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
const std::string control<pubkey_algo>::error_message =
    "signature target subpacket public key algorithm is missing";

template <>
const std::string control<hash_algo>::error_message =
    "signature target subpacket hash algorithm is missing";

template <>
const std::string control<hash>::error_message =
    "signature target subpacket hash is invalid";

template <>
const std::string control<eof>::error_message =
    "signature target subpacket is too large";

}  // namespace signature_target_subpacket
}  // namespace NeoPG

std::unique_ptr<SignatureTargetSubpacket>
SignatureTargetSubpacket::create_or_throw(ParserInput& in) {
  auto packet = NeoPG::make_unique<SignatureTargetSubpacket>();
  pegtl::parse<signature_target_subpacket::grammar,
               signature_target_subpacket::action,
               signature_target_subpacket::control>(in.m_impl->m_input,
                                                    *packet.get());

  switch (packet->m_hash_algorithm) {
    case HashAlgorithm::Md5: {
      Botan::MD5 digest;
      if (packet->m_hash.size() != digest.output_length())
        in.error("signature target subpacket hash size wrong for MD5");
      break;
    }
    case HashAlgorithm::Sha1: {
      Botan::SHA_160 digest;
      if (packet->m_hash.size() != digest.output_length())
        in.error("signature target subpacket hash size wrong for SHA-1");
      break;
    }
    case HashAlgorithm::Ripemd160: {
      Botan::RIPEMD_160 digest;
      if (packet->m_hash.size() != digest.output_length())
        in.error("signature target subpacket hash size wrong for RIPEMD-160");
      break;
    }
    case HashAlgorithm::Sha256: {
      Botan::SHA_256 digest;
      if (packet->m_hash.size() != digest.output_length())
        in.error("signature target subpacket hash size wrong for SHA-256");
      break;
    }
    case HashAlgorithm::Sha384: {
      Botan::SHA_384 digest;
      if (packet->m_hash.size() != digest.output_length())
        in.error("signature target subpacket hash size wrong for SHA-384");
      break;
    }
    case HashAlgorithm::Sha512: {
      Botan::SHA_512 digest;
      if (packet->m_hash.size() != digest.output_length())
        in.error("signature target subpacket hash size wrong for SHA-512");
      break;
    }
    case HashAlgorithm::Sha224: {
      Botan::SHA_224 digest;
      if (packet->m_hash.size() != digest.output_length())
        in.error("signature target subpacket hash size wrong for SHA-224");
      break;
    }
    default:
      // Can't tell how long the hash is.
      break;
  }
  return packet;
}

void SignatureTargetSubpacket::write_body(std::ostream& out) const {
  out << static_cast<uint8_t>(m_public_key_algorithm)
      << static_cast<uint8_t>(m_hash_algorithm);
  out.write(reinterpret_cast<const char*>(m_hash.data()), m_hash.size());
}
