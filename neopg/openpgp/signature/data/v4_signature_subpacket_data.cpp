// OpenPGP v4 signature subpacket data (implementation)
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/signature/data/v4_signature_subpacket_data.h>

#include <neopg/intern/cplusplus.h>
#include <neopg/intern/pegtl.h>
#include <neopg/utils/stream.h>

#include <botan/loadstor.h>

#include <algorithm>
#include <iterator>

using namespace NeoPG;

namespace NeoPG {
namespace v4_signature_subpacket_data {

using namespace pegtl;

template <typename Rule>
struct action : nothing<Rule> {};

struct subpacket_data {
  using analyze_t = analysis::generic<analysis::rule_type::ANY>;
  template <apply_mode A, rewind_mode M, template <typename...> class Action,
            template <typename...> class Control, typename Input>
  static bool match(Input& in,
                    std::unique_ptr<SignatureSubpacketLength>& length,
                    SignatureSubpacketType& type, bool& critical,
                    V4SignatureSubpacketData& data) {
    if (length->m_length == 0)
      throw parser_error("invalid signature subpacket length of zero", in);
    uint32_t subpacket_length = length->m_length - 1;
    if (in.size(subpacket_length) >= subpacket_length) {
      in.bump(subpacket_length);
      return true;
    }
    return false;
  }
};

struct subpacket_length_one : uint8::range<0x00, 0xbf> {};
struct subpacket_length_two : seq<uint8::range<0xc0, 0xfe>, any> {};
struct subpacket_length_five : seq<uint8::one<0xff>, bytes<4>> {};

struct subpacket_length
    : sor<subpacket_length_one, subpacket_length_two, subpacket_length_five> {};
struct subpacket_type : any {};

struct subpacket : must<subpacket_length, subpacket_type, subpacket_data> {};

struct subpacket_list : seq<until<eof, subpacket>, must<eof>> {};

template <>
struct action<subpacket_length_one> {
  template <typename Input>
  static void apply(const Input& in,
                    std::unique_ptr<SignatureSubpacketLength>& length,
                    SignatureSubpacketType& type, bool& critical,
                    V4SignatureSubpacketData& data) {
    auto val = (uint32_t)in.peek_byte(0);
    length = make_unique<SignatureSubpacketLength>(
        val, SignatureSubpacketLengthType::OneOctet);
  }
};

template <>
struct action<subpacket_length_two> {
  template <typename Input>
  static void apply(const Input& in,
                    std::unique_ptr<SignatureSubpacketLength>& length,
                    SignatureSubpacketType& type, bool& critical,
                    V4SignatureSubpacketData& data) {
    auto val0 = (uint32_t)in.peek_byte(0);
    auto val1 = (uint32_t)in.peek_byte(1);
    auto val = ((val0 - 0xc0) << 8) + val1 + 192;
    length = make_unique<SignatureSubpacketLength>(
        val, SignatureSubpacketLengthType::TwoOctet);
  }
};

template <>
struct action<subpacket_length_five> {
  template <typename Input>
  static void apply(const Input& in,
                    std::unique_ptr<SignatureSubpacketLength>& length,
                    SignatureSubpacketType& type, bool& critical,
                    V4SignatureSubpacketData& data) {
    auto src = in.begin();
    auto ptr = reinterpret_cast<const uint8_t*>(src);
    static_assert(sizeof(*src) == sizeof(*ptr), "can't do pointer arithmetic");
    auto val = Botan::load_be<uint32_t>(ptr + 1, 0);
    length = make_unique<SignatureSubpacketLength>(
        val, SignatureSubpacketLengthType::FiveOctet);
  }
};

template <>
struct action<subpacket_type> {
  template <typename Input>
  static void apply(const Input& in,
                    std::unique_ptr<SignatureSubpacketLength>& length,
                    SignatureSubpacketType& type, bool& critical,
                    V4SignatureSubpacketData& data) {
    auto val = (uint32_t)in.peek_byte(0);
    critical = (val & 0x80) ? true : false;
    type = static_cast<SignatureSubpacketType>(val & 0x7f);
  }
};

template <>
struct action<subpacket_data> {
  template <typename Input>
  static void apply(const Input& in,
                    std::unique_ptr<SignatureSubpacketLength>& length,
                    SignatureSubpacketType& type, bool& critical,
                    V4SignatureSubpacketData& data) {
    ParserInput in2(in.begin(), in.size());
    auto subpacket = SignatureSubpacket::create_or_throw(type, in2);
    subpacket->m_length = std::move(length);
    subpacket->m_critical = critical;
    data.m_subpackets.push_back(std::move(subpacket));
    // FIXME: In case of error, rewrite exception to point to byte offset.
  }
};

// A custom rule to match subpacket data.  This is stateful, because it requires
// the preceeding length information, and matches exactly subpackets_length
// bytes.
struct subpackets_data {
  using analyze_t = analysis::generic<analysis::rule_type::ANY>;
  template <apply_mode A, rewind_mode M, template <typename...> class Action,
            template <typename...> class Control, typename Input>
  static bool match(Input& in, uint16_t& subpackets_length,
                    V4SignatureSubpacketData& data) {
    if (in.size(subpackets_length) >= subpackets_length) {
      in.bump(subpackets_length);
      return true;
    }
    return false;
  }
};

struct subpackets_length : bytes<2> {};
struct subpackets : must<subpackets_length, subpackets_data> {};

// Action
template <>
struct action<subpackets_length> {
  template <typename Input>
  static void apply(const Input& in, uint16_t& length,
                    V4SignatureSubpacketData& data) {
    auto val0 = (uint32_t)in.peek_byte(0);
    auto val1 = (uint32_t)in.peek_byte(1);
    length = (val0 << 8) + val1;
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
struct action<subpackets_data> {
  template <typename Input>
  static void apply(const Input& in, uint16_t& length,
                    V4SignatureSubpacketData& data) {
    ParserInput in2(in.begin(), in.size());
    std::unique_ptr<SignatureSubpacketLength> subpacket_length;
    SignatureSubpacketType type;
    bool critical;
    pegtl::parse<v4_signature_subpacket_data::subpacket_list,
                 v4_signature_subpacket_data::action,
                 v4_signature_subpacket_data::control>(
        in2.m_impl->m_input, subpacket_length, type, critical, data);
    // FIXME: In case of error, rewrite exception to point to byte offset.
  }
};

template <>
const std::string control<subpacket>::error_message =
    "v4 signature subpacket data subpacket invalid";

template <>
const std::string control<subpackets_length>::error_message =
    "v4 signature subpacket data subpacket invalid subpackets length";

template <>
const std::string control<subpackets_data>::error_message =
    "v4 signature subpacket data invalid subpackets data";

template <>
const std::string control<subpacket_length>::error_message =
    "v4 signature subpacket data subpacket invalid subpacket length";

template <>
const std::string control<subpacket_data>::error_message =
    "v4 signature subpacket data invalid subpacket data";

template <>
const std::string control<subpacket_type>::error_message =
    "v4 signature subpacket data invalid subpacket type";

template <>
const std::string control<eof>::error_message =
    "v4 signature subpacket data has trailing data";

}  // namespace v4_signature_subpacket_data
}  // namespace NeoPG

std::unique_ptr<V4SignatureSubpacketData>
V4SignatureSubpacketData::create_or_throw(ParserInput& in) {
  auto data = make_unique<V4SignatureSubpacketData>();
  uint16_t length;
  pegtl::parse<v4_signature_subpacket_data::subpackets,
               v4_signature_subpacket_data::action,
               v4_signature_subpacket_data::control>(in.m_impl->m_input, length,
                                                     *data);
  return data;
}

void V4SignatureSubpacketData::write(std::ostream& out) const {
  CountingStream cnt;
  for (const auto& subpacket : m_subpackets) subpacket->write(cnt);
  uint32_t len = cnt.bytes_written();
  if (len >= 1 << 16) throw std::length_error("Subpacket data too large");
  out << static_cast<uint8_t>(len >> 8) << static_cast<uint8_t>(len);
  for (const auto& subpacket : m_subpackets) subpacket->write(out);
}
