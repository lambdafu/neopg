// OpenPGP issuer subpacket (implementation)
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/signature/subpacket/issuer_subpacket.h>

#include <neopg/parser/parser_input.h>
#include <neopg/utils/stream.h>

#include <neopg/intern/cplusplus.h>
#include <neopg/intern/pegtl.h>

using namespace NeoPG;

namespace NeoPG {
namespace issuer_subpacket {

using namespace pegtl;

// Grammar
struct issuer : bytes<8> {};
struct grammar : must<issuer, eof> {};

// Action

template <typename Rule>
struct action : nothing<Rule> {};

template <>
struct action<issuer>
    : bind<IssuerSubpacket, std::vector<uint8_t>, &IssuerSubpacket::m_issuer> {
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
const std::string control<issuer>::error_message =
    "issuer subpacket is invalid";

template <>
const std::string control<eof>::error_message = "issuer subpacket is too large";

}  // namespace issuer_subpacket
}  // namespace NeoPG

std::unique_ptr<IssuerSubpacket> IssuerSubpacket::create_or_throw(
    ParserInput& in) {
  auto packet = NeoPG::make_unique<IssuerSubpacket>();
  pegtl::parse<issuer_subpacket::grammar, issuer_subpacket::action,
               issuer_subpacket::control>(in.m_impl->m_input, *packet.get());
  return packet;
}

void IssuerSubpacket::write_body(std::ostream& out) const {
  out.write(reinterpret_cast<const char*>(m_issuer.data()), m_issuer.size());
}
