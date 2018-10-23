// OpenPGP signature packet (implementation)
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/signature_packet.h>

#include <neopg/intern/cplusplus.h>
#include <neopg/intern/pegtl.h>

using namespace NeoPG;

namespace NeoPG {
namespace signature_packet {

using namespace pegtl;

// Grammar
struct version : any {};
struct grammar : must<version> {};

// In this case, we don't use nested parsing, because we don't know the size of
// the public key data ahead of time. After parsing the public key material
// we reenter here.
struct end : must<eof> {};

// Action
template <typename Rule>
struct action : nothing<Rule> {};

template <>
struct action<version>
    : bind<SignaturePacket, SignatureVersion, &SignaturePacket::m_version> {};

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
    "signature packet has invalid version number";

template <>
const std::string control<eof>::error_message = "signature packet is too large";

}  // namespace signature_packet
}  // namespace NeoPG

std::unique_ptr<SignaturePacket> SignaturePacket::create(ParserInput& in) {
  try {
    return SignaturePacket::create_or_throw(in);
  } catch (const ParserError&) {
    return nullptr;
  }
}

std::unique_ptr<SignaturePacket> SignaturePacket::create_or_throw(
    ParserInput& in) {
  auto packet = make_unique<SignaturePacket>();
  pegtl::parse<signature_packet::grammar, signature_packet::action,
               signature_packet::control>(in.m_impl->m_input, *packet.get());
  packet->m_signature = SignatureData::create_or_throw(packet->version(), in);
  pegtl::parse<signature_packet::end, signature_packet::action,
               signature_packet::control>(in.m_impl->m_input, *packet.get());
  return packet;
}

void SignaturePacket::write_body(std::ostream& out) const {
  out << static_cast<uint8_t>(m_version);
  if (m_signature) m_signature->write(out);
}
