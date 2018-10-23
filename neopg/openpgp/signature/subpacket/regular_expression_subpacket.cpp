// OpenPGP regular expression subpacket (implementation)
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/signature/subpacket/regular_expression_subpacket.h>

#include <neopg/parser/parser_input.h>
#include <neopg/utils/stream.h>

#include <neopg/intern/cplusplus.h>
#include <neopg/intern/pegtl.h>

using namespace NeoPG;

namespace NeoPG {
namespace regular_expression_subpacket {

using namespace pegtl;

// Grammar
struct regex : rep_max_any<RegularExpressionSubpacket::MAX_LENGTH> {};
struct grammar : must<regex, eof> {};

// Action

template <typename Rule>
struct action : nothing<Rule> {};

template <>
struct action<regex> : bind<RegularExpressionSubpacket, std::string,
                            &RegularExpressionSubpacket::m_regex> {};

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
const std::string control<regex>::error_message =
    "regular expression subpacket is invalid";

template <>
const std::string control<eof>::error_message =
    "regular expression subpacket is too large";

}  // namespace regular_expression_subpacket
}  // namespace NeoPG

std::unique_ptr<RegularExpressionSubpacket>
RegularExpressionSubpacket::create_or_throw(ParserInput& in) {
  auto packet = NeoPG::make_unique<RegularExpressionSubpacket>();
  pegtl::parse<regular_expression_subpacket::grammar,
               regular_expression_subpacket::action,
               regular_expression_subpacket::control>(in.m_impl->m_input,
                                                      *packet.get());
  return packet;
}

void RegularExpressionSubpacket::write_body(std::ostream& out) const {
  out << m_regex;
}
