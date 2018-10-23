// OpenPGP revocation key subpacket (implementation)
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/signature/subpacket/revocation_key_subpacket.h>

#include <neopg/parser/parser_input.h>
#include <neopg/utils/stream.h>

#include <neopg/intern/cplusplus.h>
#include <neopg/intern/pegtl.h>

using namespace NeoPG;

namespace NeoPG {
namespace revocation_key_subpacket {

using namespace pegtl;

// Grammar
struct the_class : any {};
struct algorithm : any {};
struct fingerprint : bytes<20> {};
struct grammar : must<the_class, algorithm, fingerprint, eof> {};

// Action
template <typename Rule>
struct action : nothing<Rule> {};

template <>
struct action<the_class>
    : bind<RevocationKeySubpacket, uint8_t, &RevocationKeySubpacket::m_class> {
};

template <>
struct action<algorithm> : bind<RevocationKeySubpacket, PublicKeyAlgorithm,
                                &RevocationKeySubpacket::m_algorithm> {};

template <>
struct action<fingerprint> : bind<RevocationKeySubpacket, std::vector<uint8_t>,
                                  &RevocationKeySubpacket::m_fingerprint> {};

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
const std::string control<the_class>::error_message =
    "revocation key subpacket class is missing";

template <>
const std::string control<algorithm>::error_message =
    "revocation key subpacket algorithm is missing";

template <>
const std::string control<fingerprint>::error_message =
    "revocation key subpacket class is invalid";

template <>
const std::string control<eof>::error_message =
    "revocation key subpacket is too large";

}  // namespace revocation_key_subpacket
}  // namespace NeoPG

std::unique_ptr<RevocationKeySubpacket> RevocationKeySubpacket::create_or_throw(
    ParserInput& in) {
  auto packet = NeoPG::make_unique<RevocationKeySubpacket>();
  pegtl::parse<revocation_key_subpacket::grammar,
               revocation_key_subpacket::action,
               revocation_key_subpacket::control>(in.m_impl->m_input,
                                                  *packet.get());
  return packet;
}

void RevocationKeySubpacket::write_body(std::ostream& out) const {
  out << m_class << static_cast<uint8_t>(m_algorithm);
  out.write(reinterpret_cast<const char*>(m_fingerprint.data()),
            m_fingerprint.size());
}
