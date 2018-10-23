// OpenPGP signature creation time subpacket (implementation)
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/signature/subpacket/signature_creation_time_subpacket.h>

#include <neopg/parser/parser_input.h>
#include <neopg/utils/stream.h>

#include <neopg/intern/cplusplus.h>
#include <neopg/intern/pegtl.h>

using namespace NeoPG;

namespace NeoPG {
namespace signature_creation_time_subpacket {

using namespace pegtl;

// Grammar
struct created : bytes<4> {};
struct grammar : must<created, eof> {};

// Action
template <typename Rule>
struct action : nothing<Rule> {};

template <>
struct action<created> : bind<SignatureCreationTimeSubpacket, uint32_t,
                              &SignatureCreationTimeSubpacket::m_created> {};

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
const std::string control<created>::error_message =
    "signature creation time subpacket is invalid";

template <>
const std::string control<eof>::error_message =
    "signature creation time subpacket is too large";

}  // namespace signature_creation_time_subpacket
}  // namespace NeoPG

std::unique_ptr<SignatureCreationTimeSubpacket>
SignatureCreationTimeSubpacket::create_or_throw(ParserInput& in) {
  auto packet = NeoPG::make_unique<SignatureCreationTimeSubpacket>();
  pegtl::parse<signature_creation_time_subpacket::grammar,
               signature_creation_time_subpacket::action,
               signature_creation_time_subpacket::control>(in.m_impl->m_input,
                                                           *packet.get());
  return packet;
}

void SignatureCreationTimeSubpacket::write_body(std::ostream& out) const {
  out << static_cast<uint8_t>(m_created >> 24)
      << static_cast<uint8_t>(m_created >> 16)
      << static_cast<uint8_t>(m_created >> 8)
      << static_cast<uint8_t>(m_created);
}
