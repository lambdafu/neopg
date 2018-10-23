// OpenPGP raw signature subpacket (implementation)
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/signature/subpacket/raw_signature_subpacket.h>

#include <neopg/parser/parser_input.h>
#include <neopg/utils/stream.h>

#include <neopg/intern/cplusplus.h>
#include <neopg/intern/pegtl.h>

using namespace NeoPG;

namespace NeoPG {
namespace raw_signature_subpacket {

using namespace pegtl;

// Grammar
struct content : rep_max_any<RawSignatureSubpacket::MAX_LENGTH> {};
struct grammar : must<content, eof> {};

// Action

template <typename Rule>
struct action : nothing<Rule> {};

template <>
struct action<content> : bind<RawSignatureSubpacket, std::string,
                              &RawSignatureSubpacket::m_content> {};

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
const std::string control<content>::error_message =
    "signature subpacket is invalid";

template <>
const std::string control<eof>::error_message =
    "signature subpacket is too large";

}  // namespace raw_signature_subpacket
}  // namespace NeoPG

std::unique_ptr<RawSignatureSubpacket> RawSignatureSubpacket::create_or_throw(
    SignatureSubpacketType type, ParserInput& in) {
  auto packet = NeoPG::make_unique<RawSignatureSubpacket>();
  packet->m_type = type;
  pegtl::parse<raw_signature_subpacket::grammar,
               raw_signature_subpacket::action,
               raw_signature_subpacket::control>(in.m_impl->m_input,
                                                 *packet.get());
  return packet;
}

void RawSignatureSubpacket::write_body(std::ostream& out) const {
  out.write(reinterpret_cast<const char*>(m_content.data()), m_content.size());
}
