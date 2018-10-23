// OpenPGP revocable subpacket (implementation)
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/signature/subpacket/revocable_subpacket.h>

#include <neopg/parser/parser_input.h>
#include <neopg/utils/stream.h>

#include <neopg/intern/cplusplus.h>
#include <neopg/intern/pegtl.h>

using namespace NeoPG;

namespace NeoPG {
namespace revocable_subpacket {

using namespace pegtl;

// Grammar
struct revocable : any {};
struct grammar : must<revocable, eof> {};

// Action
template <typename Rule>
struct action : nothing<Rule> {};

template <>
struct action<revocable>
    : bind<RevocableSubpacket, uint8_t, &RevocableSubpacket::m_revocable> {};

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
const std::string control<revocable>::error_message =
    "revocable subpacket is invalid";

template <>
const std::string control<eof>::error_message =
    "revocable subpacket is too large";

}  // namespace revocable_subpacket
}  // namespace NeoPG

std::unique_ptr<RevocableSubpacket> RevocableSubpacket::create_or_throw(
    ParserInput& in) {
  auto packet = NeoPG::make_unique<RevocableSubpacket>();
  pegtl::parse<revocable_subpacket::grammar, revocable_subpacket::action,
               revocable_subpacket::control>(in.m_impl->m_input, *packet.get());
  return packet;
}

void RevocableSubpacket::write_body(std::ostream& out) const {
  out << static_cast<uint8_t>(m_revocable);
}
