// OpenPGP raw signature material (implementation)
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/signature/material/raw_signature_material.h>

#include <neopg/intern/cplusplus.h>
#include <neopg/intern/pegtl.h>

using namespace NeoPG;

namespace NeoPG {
namespace raw_signature_material {

using namespace pegtl;

// Grammar
struct content : rep_max_any<RawSignatureMaterial::MAX_LENGTH> {};
struct grammar : must<content, eof> {};

// Action

template <typename Rule>
struct action : nothing<Rule> {};

template <>
struct action<content> : bind<RawSignatureMaterial, std::vector<uint8_t>,
                              &RawSignatureMaterial::m_content> {};

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
    "raw signature material is invalid";

template <>
const std::string control<eof>::error_message =
    "raw signature material is too large";

}  // namespace raw_signature_material
}  // namespace NeoPG

std::unique_ptr<RawSignatureMaterial> RawSignatureMaterial::create_or_throw(
    PublicKeyAlgorithm algorithm, ParserInput& in) {
  auto data = make_unique<RawSignatureMaterial>();
  data->m_algorithm = algorithm;
  pegtl::parse<raw_signature_material::grammar, raw_signature_material::action,
               raw_signature_material::control>(in.m_impl->m_input,
                                                *data.get());
  return data;
}

void RawSignatureMaterial::write(std::ostream& out) const {
  out.write(reinterpret_cast<const char*>(m_content.data()), m_content.size());
}
