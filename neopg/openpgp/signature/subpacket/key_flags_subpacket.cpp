// OpenPGP key flags subpacket (implementation)
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/signature/subpacket/key_flags_subpacket.h>

#include <neopg/parser/parser_input.h>
#include <neopg/utils/stream.h>

#include <neopg/intern/cplusplus.h>
#include <neopg/intern/pegtl.h>

using namespace NeoPG;

namespace NeoPG {
namespace key_flags_subpacket {

using namespace pegtl;

// Grammar
struct flags : rep_max_any<KeyFlagsSubpacket::MAX_LENGTH> {};
struct grammar : must<flags, eof> {};

// Action

template <typename Rule>
struct action : nothing<Rule> {};

template <>
struct action<flags> : bind<KeyFlagsSubpacket, std::vector<uint8_t>,
                            &KeyFlagsSubpacket::m_flags> {};

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
const std::string control<flags>::error_message =
    "key flags subpacket is invalid";

template <>
const std::string control<eof>::error_message =
    "key flags subpacket is too large";

}  // namespace key_flags_subpacket
}  // namespace NeoPG

std::unique_ptr<KeyFlagsSubpacket> KeyFlagsSubpacket::create_or_throw(
    ParserInput& in) {
  auto packet = NeoPG::make_unique<KeyFlagsSubpacket>();
  pegtl::parse<key_flags_subpacket::grammar, key_flags_subpacket::action,
               key_flags_subpacket::control>(in.m_impl->m_input, *packet.get());
  return packet;
}

void KeyFlagsSubpacket::write_body(std::ostream& out) const {
  out.write(reinterpret_cast<const char*>(m_flags.data()), m_flags.size());
}
