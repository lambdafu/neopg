// OpenPGP marker packet (implementation)
// Copyright 2017-2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/marker_packet.h>
#include <neopg/parser/parser_error.h>

#include <neopg/intern/cplusplus.h>
#include <neopg/intern/pegtl.h>

using namespace NeoPG;

// Must be a string literal.
#define MARKER "PGP"

namespace NeoPG {
namespace marker_packet {

using namespace pegtl;

// Grammar
struct marker : TAO_PEGTL_STRING(MARKER) {};
struct grammar : must<marker, eof> {};

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
const std::string control<marker>::error_message =
    "marker packet is missing marker";

template <>
const std::string control<eof>::error_message =
    "marker packet has trailing data";

}  // namespace marker_packet
}  // namespace NeoPG

std::unique_ptr<MarkerPacket> MarkerPacket::create(ParserInput& in) {
  try {
    return MarkerPacket::create_or_throw(in);
  } catch (const ParserError&) {
    return nullptr;
  }
}

std::unique_ptr<MarkerPacket> MarkerPacket::create_or_throw(ParserInput& in) {
  pegtl::parse<marker_packet::grammar, pegtl::nothing, marker_packet::control>(
      in.m_impl->m_input);
  return NeoPG::make_unique<MarkerPacket>();
}

void MarkerPacket::write_body(std::ostream& out) const { out << MARKER; }
