// OpenPGP embedded signature subpacket (implementation)
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/signature/subpacket/embedded_signature_subpacket.h>

#include <neopg/parser/parser_input.h>
#include <neopg/utils/stream.h>

#include <neopg/intern/cplusplus.h>
#include <neopg/intern/pegtl.h>

using namespace NeoPG;

namespace NeoPG {
namespace embedded_signature_subpacket {

using namespace pegtl;

// Grammar
struct signature : rep_max_any<EmbeddedSignatureSubpacket::MAX_LENGTH> {};
struct grammar : must<signature, eof> {};

// Action

template <typename Rule>
struct action : nothing<Rule> {};

template <>
struct action<signature>
    : bind<EmbeddedSignatureSubpacket, std::vector<uint8_t>,
           &EmbeddedSignatureSubpacket::m_signature> {};

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
const std::string control<signature>::error_message =
    "embedded signature subpacket is invalid";

template <>
const std::string control<eof>::error_message =
    "embedded signature subpacket is too large";

}  // namespace embedded_signature_subpacket
}  // namespace NeoPG

std::unique_ptr<EmbeddedSignatureSubpacket>
EmbeddedSignatureSubpacket::create_or_throw(ParserInput& in) {
  auto packet = NeoPG::make_unique<EmbeddedSignatureSubpacket>();
  pegtl::parse<embedded_signature_subpacket::grammar,
               embedded_signature_subpacket::action,
               embedded_signature_subpacket::control>(in.m_impl->m_input,
                                                      *packet.get());
  return packet;
}

void EmbeddedSignatureSubpacket::write_body(std::ostream& out) const {
  out.write(reinterpret_cast<const char*>(m_signature.data()),
            m_signature.size());
}
