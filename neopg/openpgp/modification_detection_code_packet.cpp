// OpenPGP MDC packet (implementation)
// Copyright 2017-2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/modification_detection_code_packet.h>

#include <neopg/intern/cplusplus.h>
#include <neopg/intern/pegtl.h>

#include <algorithm>

using namespace NeoPG;

namespace tao {
namespace TAO_PEGTL_NAMESPACE {

template <typename T, std::array<uint8_t, 20> T::*Field>
struct bind<T, std::array<uint8_t, 20>, Field> {
  template <typename Input>
  static void apply(const Input& in, T& pkt) {
    std::copy(in.begin(), in.end(), (pkt.*Field).begin());
  }
};

}  // namespace TAO_PEGTL_NAMESPACE
}  // namespace tao

namespace NeoPG {
namespace mdc_packet {

using namespace pegtl;

// Grammar
struct mdc : bytes<ModificationDetectionCodePacket::LENGTH> {};
struct grammar : must<mdc, eof> {};

// Action
template <typename Rule>
struct action : nothing<Rule> {};

template <>
struct action<mdc>
    : bind<ModificationDetectionCodePacket,
           std::array<uint8_t, ModificationDetectionCodePacket::LENGTH>,
           &ModificationDetectionCodePacket::m_mdc> {};

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
const std::string control<mdc>::error_message = "mdc packet is invalid";

template <>
const std::string control<eof>::error_message = "mdc packet is too large";

}  // namespace mdc_packet
}  // namespace NeoPG

std::unique_ptr<ModificationDetectionCodePacket>
ModificationDetectionCodePacket::create(ParserInput& in) {
  try {
    return ModificationDetectionCodePacket::create_or_throw(in);
  } catch (const ParserError&) {
    return nullptr;
  }
}

std::unique_ptr<ModificationDetectionCodePacket>
ModificationDetectionCodePacket::create_or_throw(ParserInput& in) {
  auto packet = NeoPG::make_unique<ModificationDetectionCodePacket>();

  pegtl::parse<mdc_packet::grammar, mdc_packet::action, mdc_packet::control>(
      in.m_impl->m_input, *packet.get());
  return packet;
}

void ModificationDetectionCodePacket::write_body(std::ostream& out) const {
  out.write(reinterpret_cast<const char*>(m_mdc.data()), m_mdc.size());
}
