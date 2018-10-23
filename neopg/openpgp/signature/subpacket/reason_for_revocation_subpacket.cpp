// OpenPGP reason for revocation subpacket (implementation)
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/signature/subpacket/reason_for_revocation_subpacket.h>

#include <neopg/parser/parser_input.h>
#include <neopg/utils/stream.h>

#include <neopg/intern/cplusplus.h>
#include <neopg/intern/pegtl.h>

using namespace NeoPG;

namespace NeoPG {
namespace reason_for_revocation_subpacket {

using namespace pegtl;

// Grammar
struct code : any {};
struct reason : rep_max_any<ReasonForRevocationSubpacket::MAX_LENGTH> {};
struct grammar : must<code, reason, eof> {};

// Action

template <typename Rule>
struct action : nothing<Rule> {};

template <>
struct action<code> : bind<ReasonForRevocationSubpacket, RevocationCode,
                           &ReasonForRevocationSubpacket::m_code> {};

template <>
struct action<reason> : bind<ReasonForRevocationSubpacket, std::string,
                             &ReasonForRevocationSubpacket::m_reason> {};

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
const std::string control<code>::error_message =
    "reason for revocation subpacket code is missing";

// Unreachable, because rep_max_any always succeeds. But pegtl does not know
// that, so add an error message to silence a compiler warning/error.
template <>
const std::string control<reason>::error_message =
    "reason for revocation subpacket string is invalid";

template <>
const std::string control<eof>::error_message =
    "reason for revocation subpacket is too large";

}  // namespace reason_for_revocation_subpacket
}  // namespace NeoPG

std::unique_ptr<ReasonForRevocationSubpacket>
ReasonForRevocationSubpacket::create_or_throw(ParserInput& in) {
  auto packet = NeoPG::make_unique<ReasonForRevocationSubpacket>();
  pegtl::parse<reason_for_revocation_subpacket::grammar,
               reason_for_revocation_subpacket::action,
               reason_for_revocation_subpacket::control>(in.m_impl->m_input,
                                                         *packet.get());
  return packet;
}

void ReasonForRevocationSubpacket::write_body(std::ostream& out) const {
  out << static_cast<uint8_t>(m_code) << m_reason;
}
