// OpenPGP primary user id subpacket (implementation)
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/signature/subpacket/primary_user_id_subpacket.h>

#include <neopg/parser/parser_input.h>
#include <neopg/utils/stream.h>

#include <neopg/intern/cplusplus.h>
#include <neopg/intern/pegtl.h>

using namespace NeoPG;

namespace NeoPG {
namespace primary_user_id_subpacket {

using namespace pegtl;

// Grammar
struct primary : any {};
struct grammar : must<primary, eof> {};

// Action
template <typename Rule>
struct action : nothing<Rule> {};

template <>
struct action<primary> : bind<PrimaryUserIdSubpacket, uint8_t,
                              &PrimaryUserIdSubpacket::m_primary> {};

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
const std::string control<primary>::error_message =
    "primary user id subpacket is invalid";

template <>
const std::string control<eof>::error_message =
    "primary user id subpacket is too large";

}  // namespace primary_user_id_subpacket
}  // namespace NeoPG

std::unique_ptr<PrimaryUserIdSubpacket> PrimaryUserIdSubpacket::create_or_throw(
    ParserInput& in) {
  auto packet = NeoPG::make_unique<PrimaryUserIdSubpacket>();
  pegtl::parse<primary_user_id_subpacket::grammar,
               primary_user_id_subpacket::action,
               primary_user_id_subpacket::control>(in.m_impl->m_input,
                                                   *packet.get());
  return packet;
}

void PrimaryUserIdSubpacket::write_body(std::ostream& out) const {
  out << static_cast<uint8_t>(m_primary);
}
