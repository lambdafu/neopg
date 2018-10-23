// OpenPGP user ID packet (implementation)
// Copyright 2017-2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/packet_header.h>
#include <neopg/openpgp/user_id_packet.h>

#include <neopg/intern/cplusplus.h>
#include <neopg/intern/pegtl.h>

using namespace NeoPG;

namespace NeoPG {
namespace user_id_packet {

using namespace pegtl;

// Grammar
struct content : rep_max_any<UserIdPacket::MAX_LENGTH> {};
struct grammar : must<content, eof> {};

// Action

template <typename Rule>
struct action : nothing<Rule> {};

template <>
struct action<content>
    : bind<UserIdPacket, std::string, &UserIdPacket::m_content> {};

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
const std::string control<content>::error_message = "user id packet is invalid";

template <>
const std::string control<eof>::error_message = "user id packet is too large";

}  // namespace user_id_packet
}  // namespace NeoPG

std::unique_ptr<UserIdPacket> UserIdPacket::create(ParserInput& in) {
  try {
    return UserIdPacket::create_or_throw(in);
  } catch (const ParserError&) {
    return nullptr;
  }
}

std::unique_ptr<UserIdPacket> UserIdPacket::create_or_throw(ParserInput& in) {
  auto packet = NeoPG::make_unique<UserIdPacket>();
  pegtl::parse<user_id_packet::grammar, user_id_packet::action,
               user_id_packet::control>(in.m_impl->m_input, *packet.get());
  return packet;
}

void UserIdPacket::write_body(std::ostream& out) const {
  out.write(m_content.data(), m_content.size());
}
