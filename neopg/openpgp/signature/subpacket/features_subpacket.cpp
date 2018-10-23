// OpenPGP features subpacket (implementation)
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/signature/subpacket/features_subpacket.h>

#include <neopg/parser/parser_input.h>
#include <neopg/utils/stream.h>

#include <neopg/intern/cplusplus.h>
#include <neopg/intern/pegtl.h>

using namespace NeoPG;

namespace NeoPG {
namespace features_subpacket {

using namespace pegtl;

// Grammar
struct features : rep_max_any<FeaturesSubpacket::MAX_LENGTH> {};
struct grammar : must<features, eof> {};

// Action

template <typename Rule>
struct action : nothing<Rule> {};

template <>
struct action<features> : bind<FeaturesSubpacket, std::vector<uint8_t>,
                               &FeaturesSubpacket::m_features> {};

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
const std::string control<features>::error_message =
    "features subpacket is invalid";

template <>
const std::string control<eof>::error_message =
    "features subpacket is too large";

}  // namespace features_subpacket
}  // namespace NeoPG

std::unique_ptr<FeaturesSubpacket> FeaturesSubpacket::create_or_throw(
    ParserInput& in) {
  auto packet = NeoPG::make_unique<FeaturesSubpacket>();
  pegtl::parse<features_subpacket::grammar, features_subpacket::action,
               features_subpacket::control>(in.m_impl->m_input, *packet.get());
  return packet;
}

void FeaturesSubpacket::write_body(std::ostream& out) const {
  out.write(reinterpret_cast<const char*>(m_features.data()),
            m_features.size());
}
