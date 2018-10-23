// OpenPGP notation data subpacket (implementation)
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/signature/subpacket/notation_data_subpacket.h>

#include <neopg/parser/parser_input.h>
#include <neopg/utils/stream.h>

#include <neopg/intern/cplusplus.h>
#include <neopg/intern/pegtl.h>

#include <botan/loadstor.h>

using namespace NeoPG;

namespace NeoPG {
namespace notation_data_subpacket {

using namespace pegtl;

// A custom rule to match the notation data.  This is stateful, because it
// requires the preceeding length information, and matches exactly length bytes.
struct name {
  using analyze_t = analysis::generic<analysis::rule_type::ANY>;
  template <apply_mode A, rewind_mode M, template <typename...> class Action,
            template <typename...> class Control, typename Input>
  static bool match(Input& in, NotationDataSubpacket& sub) {
    size_t len = sub.m_name.size();
    if (in.size(len) >= len) {
      in.bump(len);
      return true;
    }
    return false;
  }
};

struct value {
  using analyze_t = analysis::generic<analysis::rule_type::ANY>;
  template <apply_mode A, rewind_mode M, template <typename...> class Action,
            template <typename...> class Control, typename Input>
  static bool match(Input& in, NotationDataSubpacket& sub) {
    size_t len = sub.m_value.size();
    if (in.size(len) >= len) {
      in.bump(len);
      return true;
    }
    return false;
  }
};

// Grammar
struct flags : bytes<4> {};
struct name_length : bytes<2> {};
struct value_length : bytes<2> {};
struct grammar : must<flags, name_length, value_length, name, value, eof> {};

// Action
template <typename Rule>
struct action : nothing<Rule> {};

template <>
struct action<name_length> {
  template <typename Input>
  static void apply(const Input& in, NotationDataSubpacket& sub) {
    auto src = in.begin();
    auto ptr = reinterpret_cast<const uint8_t*>(src);
    static_assert(sizeof(*src) == sizeof(*ptr), "can't do pointer arithmetic");
    sub.m_name.resize(Botan::load_be<uint16_t>(ptr, 0));
  }
};

template <>
struct action<value_length> {
  template <typename Input>
  static void apply(const Input& in, NotationDataSubpacket& sub) {
    auto src = in.begin();
    auto ptr = reinterpret_cast<const uint8_t*>(src);
    static_assert(sizeof(*src) == sizeof(*ptr), "can't do pointer arithmetic");
    sub.m_value.resize(Botan::load_be<uint16_t>(ptr, 0));
  }
};

template <>
struct action<flags> : bind<NotationDataSubpacket, std::vector<uint8_t>,
                            &NotationDataSubpacket::m_flags> {};

template <>
struct action<name> : bind<NotationDataSubpacket, std::vector<uint8_t>,
                           &NotationDataSubpacket::m_name> {};

template <>
struct action<value> : bind<NotationDataSubpacket, std::vector<uint8_t>,
                            &NotationDataSubpacket::m_value> {};

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
const std::string control<flags>::error_message =
    "notation data subpacket is invalid";

template <>
const std::string control<name_length>::error_message =
    "notation data subpacket name length is invalid";

template <>
const std::string control<value_length>::error_message =
    "notation data subpacket value length is invalid";

template <>
const std::string control<name>::error_message =
    "notation data subpacket name is invalid";

template <>
const std::string control<value>::error_message =
    "notation data subpacket value is invalid";

template <>
const std::string control<eof>::error_message =
    "notation data subpacket is too large";

}  // namespace notation_data_subpacket
}  // namespace NeoPG

std::unique_ptr<NotationDataSubpacket> NotationDataSubpacket::create_or_throw(
    ParserInput& in) {
  auto packet = NeoPG::make_unique<NotationDataSubpacket>();
  pegtl::parse<notation_data_subpacket::grammar,
               notation_data_subpacket::action,
               notation_data_subpacket::control>(in.m_impl->m_input,
                                                 *packet.get());
  return packet;
}

void NotationDataSubpacket::write_body(std::ostream& out) const {
  uint16_t name_len = m_name.size();
  uint16_t value_len = m_value.size();

  out.write(reinterpret_cast<const char*>(m_flags.data()), m_flags.size());
  out << static_cast<uint8_t>(name_len >> 8) << static_cast<uint8_t>(name_len)
      << static_cast<uint8_t>(value_len >> 8)
      << static_cast<uint8_t>(value_len);
  out.write(reinterpret_cast<const char*>(m_name.data()), m_name.size());
  out.write(reinterpret_cast<const char*>(m_value.data()), m_value.size());
}
