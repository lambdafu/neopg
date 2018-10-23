// OpenPGP signers user id subpacket (implementation)
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/signature/subpacket/signers_user_id_subpacket.h>

#include <neopg/parser/parser_input.h>
#include <neopg/utils/stream.h>

#include <neopg/intern/cplusplus.h>
#include <neopg/intern/pegtl.h>

using namespace NeoPG;

namespace NeoPG {
namespace signers_user_id_subpacket {

using namespace pegtl;

// Grammar
struct user_id : rep_max_any<SignersUserIdSubpacket::MAX_LENGTH> {};
struct grammar : must<user_id, eof> {};

// Action

template <typename Rule>
struct action : nothing<Rule> {};

template <>
struct action<user_id> : bind<SignersUserIdSubpacket, std::string,
                              &SignersUserIdSubpacket::m_user_id> {};

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
const std::string control<user_id>::error_message =
    "signers user id subpacket is invalid";

template <>
const std::string control<eof>::error_message =
    "signers user id subpacket is too large";

}  // namespace signers_user_id_subpacket
}  // namespace NeoPG

std::unique_ptr<SignersUserIdSubpacket> SignersUserIdSubpacket::create_or_throw(
    ParserInput& in) {
  auto packet = NeoPG::make_unique<SignersUserIdSubpacket>();
  pegtl::parse<signers_user_id_subpacket::grammar,
               signers_user_id_subpacket::action,
               signers_user_id_subpacket::control>(in.m_impl->m_input,
                                                   *packet.get());
  return packet;
}

void SignersUserIdSubpacket::write_body(std::ostream& out) const {
  out << m_user_id;
}
