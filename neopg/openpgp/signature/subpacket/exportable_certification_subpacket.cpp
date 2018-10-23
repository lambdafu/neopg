// OpenPGP exportable certification subpacket (implementation)
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/signature/subpacket/exportable_certification_subpacket.h>

#include <neopg/parser/parser_input.h>
#include <neopg/utils/stream.h>

#include <neopg/intern/cplusplus.h>
#include <neopg/intern/pegtl.h>

using namespace NeoPG;

namespace NeoPG {
namespace exportable_certification_subpacket {

using namespace pegtl;

// Grammar
struct exportable : any {};
struct grammar : must<exportable, eof> {};

// Action
template <typename Rule>
struct action : nothing<Rule> {};

template <>
struct action<exportable>
    : bind<ExportableCertificationSubpacket, uint8_t,
           &ExportableCertificationSubpacket::m_exportable> {};

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
const std::string control<exportable>::error_message =
    "exportable certification subpacket is invalid";

template <>
const std::string control<eof>::error_message =
    "exportable certification subpacket is too large";

}  // namespace exportable_certification_subpacket
}  // namespace NeoPG

std::unique_ptr<ExportableCertificationSubpacket>
ExportableCertificationSubpacket::create_or_throw(ParserInput& in) {
  auto packet = NeoPG::make_unique<ExportableCertificationSubpacket>();
  pegtl::parse<exportable_certification_subpacket::grammar,
               exportable_certification_subpacket::action,
               exportable_certification_subpacket::control>(in.m_impl->m_input,
                                                            *packet.get());
  return packet;
}

void ExportableCertificationSubpacket::write_body(std::ostream& out) const {
  out << m_exportable;
}
