// OpenPGP trust signature subpacket (implementation)
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/signature/subpacket/trust_signature_subpacket.h>

#include <neopg/parser/parser_input.h>
#include <neopg/utils/stream.h>

#include <neopg/intern/cplusplus.h>
#include <neopg/intern/pegtl.h>

using namespace NeoPG;

namespace NeoPG {
namespace trust_signature_subpacket {

using namespace pegtl;

// Grammar
struct level : any {};
struct amount : any {};
struct grammar : must<level, amount, eof> {};

// Action
template <typename Rule>
struct action : nothing<Rule> {};

template <>
struct action<level> : bind<TrustSignatureSubpacket, uint8_t,
                            &TrustSignatureSubpacket::m_level> {};

template <>
struct action<amount> : bind<TrustSignatureSubpacket, uint8_t,
                             &TrustSignatureSubpacket::m_amount> {};

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
const std::string control<level>::error_message =
    "trust signature subpacket level is missing";

template <>
const std::string control<amount>::error_message =
    "trust signature subpacket amount is missing";

template <>
const std::string control<eof>::error_message =
    "trust signature subpacket is too large";

}  // namespace trust_signature_subpacket
}  // namespace NeoPG

std::unique_ptr<TrustSignatureSubpacket>
TrustSignatureSubpacket::create_or_throw(ParserInput& in) {
  auto packet = NeoPG::make_unique<TrustSignatureSubpacket>();
  pegtl::parse<trust_signature_subpacket::grammar,
               trust_signature_subpacket::action,
               trust_signature_subpacket::control>(in.m_impl->m_input,
                                                   *packet.get());
  return packet;
}

void TrustSignatureSubpacket::write_body(std::ostream& out) const {
  out << m_level << m_amount;
}
