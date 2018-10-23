// OpenPGP public subkey packet (implementation)
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/public_subkey_packet.h>

#include <neopg/intern/cplusplus.h>
#include <neopg/intern/pegtl.h>

using namespace NeoPG;

namespace NeoPG {
namespace public_subkey_packet {

using namespace pegtl;

// Grammar
struct version : any {};
struct grammar : must<version> {};

// In this case, we can't use nested parsing, because we don't know the size of
// the public key data ahead of time.
struct end : must<eof> {};

// Action
template <typename Rule>
struct action : nothing<Rule> {};

template <>
struct action<version> : bind<PublicSubkeyPacket, PublicKeyVersion,
                              &PublicSubkeyPacket::m_version> {};

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
const std::string control<version>::error_message =
    "public subkey packet has invalid version number";

template <>
const std::string control<eof>::error_message =
    "public subkey packet is too large";

}  // namespace public_subkey_packet
}  // namespace NeoPG

std::unique_ptr<PublicSubkeyPacket> PublicSubkeyPacket::create(
    ParserInput& in) {
  try {
    return PublicSubkeyPacket::create_or_throw(in);
  } catch (const ParserError&) {
    return nullptr;
  }
}

std::unique_ptr<PublicSubkeyPacket> PublicSubkeyPacket::create_or_throw(
    ParserInput& in) {
  auto packet = make_unique<PublicSubkeyPacket>();
  pegtl::parse<public_subkey_packet::version, public_subkey_packet::action,
               public_subkey_packet::control>(in.m_impl->m_input,
                                              *packet.get());
  packet->m_public_key = PublicKeyData::create_or_throw(packet->version(), in);
  pegtl::parse<public_subkey_packet::end, public_subkey_packet::action,
               public_subkey_packet::control>(in.m_impl->m_input,
                                              *packet.get());
  return packet;
}

void PublicSubkeyPacket::write_body(std::ostream& out) const {
  out << static_cast<uint8_t>(m_version);
  if (m_public_key) m_public_key->write(out);
}
