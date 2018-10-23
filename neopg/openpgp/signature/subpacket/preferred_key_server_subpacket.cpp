// OpenPGP preferred key server subpacket (implementation)
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/signature/subpacket/preferred_key_server_subpacket.h>

#include <neopg/parser/parser_input.h>
#include <neopg/utils/stream.h>

#include <neopg/intern/cplusplus.h>
#include <neopg/intern/pegtl.h>

using namespace NeoPG;

namespace NeoPG {
namespace preferred_key_server_subpacket {

using namespace pegtl;

// Grammar
struct uri : rep_max_any<PreferredKeyServerSubpacket::MAX_LENGTH> {};
struct grammar : must<uri, eof> {};

// Action

template <typename Rule>
struct action : nothing<Rule> {};

template <>
struct action<uri> : bind<PreferredKeyServerSubpacket, std::string,
                          &PreferredKeyServerSubpacket::m_uri> {};

// Control
template <typename Rule>
struct control : pegtl::normal<Rule> {
  static const std::string error_message;

  template <typename Input, typename... States>
  static void raise(const Input& in, States&&...) {
    throw parser_error(error_message, in);
  }
};

// Unreachable, because rep_max_any always succeeds. But pegtl does not know
// that, so add an error message to silence a compiler warning/error.
template <>
const std::string control<uri>::error_message =
    "preferred key server subpacket is invalid";

template <>
const std::string control<eof>::error_message =
    "preferred key server subpacket is too large";

}  // namespace preferred_key_server_subpacket
}  // namespace NeoPG

std::unique_ptr<PreferredKeyServerSubpacket>
PreferredKeyServerSubpacket::create_or_throw(ParserInput& in) {
  auto packet = NeoPG::make_unique<PreferredKeyServerSubpacket>();
  pegtl::parse<preferred_key_server_subpacket::grammar,
               preferred_key_server_subpacket::action,
               preferred_key_server_subpacket::control>(in.m_impl->m_input,
                                                        *packet.get());
  return packet;
}

void PreferredKeyServerSubpacket::write_body(std::ostream& out) const {
  out << m_uri;
}
