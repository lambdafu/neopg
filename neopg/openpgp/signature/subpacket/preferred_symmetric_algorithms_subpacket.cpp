// OpenPGP preferred symmetric algorithms subpacket (implementation)
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/signature/subpacket/preferred_symmetric_algorithms_subpacket.h>

#include <neopg/parser/parser_input.h>
#include <neopg/utils/stream.h>

#include <neopg/intern/cplusplus.h>
#include <neopg/intern/pegtl.h>

using namespace NeoPG;

namespace NeoPG {
namespace preferred_symmetric_algorithms_subpacket {

using namespace pegtl;

// Grammar
struct algorithms
    : rep_max_any<PreferredSymmetricAlgorithmsSubpacket::MAX_LENGTH> {};
struct grammar : must<algorithms, eof> {};

// Action

template <typename Rule>
struct action : nothing<Rule> {};

template <>
struct action<algorithms>
    : bind<PreferredSymmetricAlgorithmsSubpacket, std::vector<uint8_t>,
           &PreferredSymmetricAlgorithmsSubpacket::m_algorithms> {};

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
const std::string control<algorithms>::error_message =
    "preferred symmetric algorithms subpacket is invalid";

template <>
const std::string control<eof>::error_message =
    "preferred symmetric algorithms subpacket is too large";

}  // namespace preferred_symmetric_algorithms_subpacket
}  // namespace NeoPG

std::unique_ptr<PreferredSymmetricAlgorithmsSubpacket>
PreferredSymmetricAlgorithmsSubpacket::create_or_throw(ParserInput& in) {
  auto packet = NeoPG::make_unique<PreferredSymmetricAlgorithmsSubpacket>();
  pegtl::parse<preferred_symmetric_algorithms_subpacket::grammar,
               preferred_symmetric_algorithms_subpacket::action,
               preferred_symmetric_algorithms_subpacket::control>(
      in.m_impl->m_input, *packet.get());
  return packet;
}

void PreferredSymmetricAlgorithmsSubpacket::write_body(
    std::ostream& out) const {
  out.write(reinterpret_cast<const char*>(m_algorithms.data()),
            m_algorithms.size());
}
