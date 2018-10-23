// OpenPGP object identifier (implementation)
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/object_identifier.h>

#include <botan/ber_dec.h>
#include <botan/oids.h>

#include <neopg/intern/cplusplus.h>
#include <neopg/intern/pegtl.h>

using namespace NeoPG;

namespace NeoPG {
namespace oid {
using namespace pegtl;

// 0x00 and 0xff are reserved for future use.
struct length : uint8::range<0x01, 0xfe> {};

// Custom rule to match as many octets as are indicated by length.
struct oid {
  using analyze_t = analysis::generic<analysis::rule_type::ANY>;
  template <apply_mode A, rewind_mode M, template <typename...> class Action,
            template <typename...> class Control, typename Input>
  static bool match(Input& in, uint8_t& length, ObjectIdentifier& oid) {
    if (in.size(length) >= length) {
      in.bump(length);
      return true;
    }
    return false;
  }
};

struct grammar : must<length, oid> {};

template <typename Rule>
struct action : nothing<Rule> {};

template <>
struct action<length> {
  template <typename Input>
  static void apply(const Input& in, uint8_t& length, ObjectIdentifier& oid) {
    length = in.peek_byte();
  }
};

template <>
struct action<oid> {
  template <typename Input>
  static void apply(const Input& in, uint8_t& length, ObjectIdentifier& oid) {
    auto begin = reinterpret_cast<const uint8_t*>(in.begin());
    oid.m_data.assign(begin, begin + in.size());

    try {
      // Test suitability for parsing and printing.
      auto oidstr = oid.as_string();
      Botan::OID oid(oidstr);
    } catch (const Botan::Decoding_Error& exc) {
      throw parser_error(std::string("oid decoding error (") + exc.what() + ")",
                         in);
    }
  }
};

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
const std::string control<length>::error_message =
    "object identifier length is invalid";

template <>
const std::string control<oid>::error_message =
    "object identifier oid is invalid";

}  // namespace oid
}  // namespace NeoPG

const std::string ObjectIdentifier::as_string() const {
  std::vector<uint8_t> data;
  data.emplace_back(static_cast<uint8_t>(0x06));
  data.emplace_back(static_cast<uint8_t>(m_data.size()));
  data.insert(std::end(data), std::begin(m_data), std::end(m_data));

  Botan::BER_Decoder decoder(data);
  Botan::OID oid;
  oid.decode_from(decoder);
  return oid.as_string();
}

void ObjectIdentifier::write(std::ostream& out) const {
  out << static_cast<uint8_t>(m_data.size());
  out.write(reinterpret_cast<const char*>(m_data.data()), m_data.size());
}

void ObjectIdentifier::parse(ParserInput& in) {
  uint8_t length = 0;
  pegtl::parse<oid::grammar, oid::action, oid::control>(in.m_impl->m_input,
                                                        length, *this);

  // Make sure it is valid.  FIXME: Cache result?
  as_string();
}
