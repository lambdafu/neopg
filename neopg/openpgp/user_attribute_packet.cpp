// OpenPGP user attribute packet (implementation)
// Copyright 2017-2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/user_attribute_packet.h>

#include <neopg/intern/cplusplus.h>
#include <neopg/intern/pegtl.h>
#include <neopg/utils/stream.h>

#include <botan/loadstor.h>

#include <algorithm>
#include <iterator>

using namespace NeoPG;

namespace NeoPG {
namespace user_attribute_packet {

using namespace pegtl;

template <typename Rule>
struct action : nothing<Rule> {};

struct subpacket_data {
  using analyze_t = analysis::generic<analysis::rule_type::ANY>;
  template <apply_mode A, rewind_mode M, template <typename...> class Action,
            template <typename...> class Control, typename Input>
  static bool match(Input& in,
                    std::unique_ptr<UserAttributeSubpacketLength>& length,
                    UserAttributeSubpacketType& type,
                    UserAttributePacket& packet) {
    if (length->m_length == 0)
      throw parser_error("invalid user attribute subpacket length of zero", in);
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

struct subpackets : seq<until<eof, subpacket>, must<eof>> {};

template <>
struct action<subpacket_length_one> {
  template <typename Input>
  static void apply(const Input& in,
                    std::unique_ptr<UserAttributeSubpacketLength>& length,
                    UserAttributeSubpacketType& type,
                    UserAttributePacket& packet) {
    auto val = (uint32_t)in.peek_byte(0);
    length = make_unique<UserAttributeSubpacketLength>(
        val, UserAttributeSubpacketLengthType::OneOctet);
  }
};

template <>
struct action<subpacket_length_two> {
  template <typename Input>
  static void apply(const Input& in,
                    std::unique_ptr<UserAttributeSubpacketLength>& length,
                    UserAttributeSubpacketType& type,
                    UserAttributePacket& packet) {
    auto val0 = (uint32_t)in.peek_byte(0);
    auto val1 = (uint32_t)in.peek_byte(1);
    auto val = ((val0 - 0xc0) << 8) + val1 + 192;
    length = make_unique<UserAttributeSubpacketLength>(
        val, UserAttributeSubpacketLengthType::TwoOctet);
  }
};

template <>
struct action<subpacket_length_five> {
  template <typename Input>
  static void apply(const Input& in,
                    std::unique_ptr<UserAttributeSubpacketLength>& length,
                    UserAttributeSubpacketType& type,
                    UserAttributePacket& packet) {
    auto src = in.begin();
    auto ptr = reinterpret_cast<const uint8_t*>(src);
    static_assert(sizeof(*src) == sizeof(*ptr), "can't do pointer arithmetic");
    auto val = Botan::load_be<uint32_t>(ptr + 1, 0);
    length = make_unique<UserAttributeSubpacketLength>(
        val, UserAttributeSubpacketLengthType::FiveOctet);
  }
};

template <>
struct action<subpacket_type> {
  template <typename Input>
  static void apply(const Input& in,
                    std::unique_ptr<UserAttributeSubpacketLength>& length,
                    UserAttributeSubpacketType& type,
                    UserAttributePacket& packet) {
    auto val = (uint32_t)in.peek_byte(0);
    type = static_cast<UserAttributeSubpacketType>(val & 0x7f);
  }
};

template <>
struct action<subpacket_data> {
  template <typename Input>
  static void apply(const Input& in,
                    std::unique_ptr<UserAttributeSubpacketLength>& length,
                    UserAttributeSubpacketType& type,
                    UserAttributePacket& packet) {
    ParserInput in2(in.begin(), in.size());
    auto subpacket = UserAttributeSubpacket::create_or_throw(type, in2);
    subpacket->m_length = std::move(length);
    packet.m_subpackets.push_back(std::move(subpacket));
    // FIXME: In case of error, rewrite exception to point to byte offset.
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
const std::string control<subpacket>::error_message =
    "user attribute subpacket data subpacket invalid";

template <>
const std::string control<subpacket_length>::error_message =
    "user attribute subpacket data subpacket invalid subpacket length";

template <>
const std::string control<subpacket_data>::error_message =
    "user attribute subpacket data invalid subpacket data";

template <>
const std::string control<subpacket_type>::error_message =
    "user attribute subpacket data invalid subpacket type";

template <>
const std::string control<eof>::error_message =
    "user attribute subpacket data has trailing data";

}  // namespace user_attribute_packet
}  // namespace NeoPG

std::unique_ptr<UserAttributePacket> UserAttributePacket::create_or_throw(
    ParserInput& in) {
  auto packet = make_unique<UserAttributePacket>();
  std::unique_ptr<UserAttributeSubpacketLength> length;
  UserAttributeSubpacketType type;
  pegtl::parse<user_attribute_packet::subpackets, user_attribute_packet::action,
               user_attribute_packet::control>(in.m_impl->m_input, length, type,
                                               *packet.get());

  return packet;
}

void UserAttributePacket::write_body(std::ostream& out) const {
  for (const auto& subpacket : m_subpackets) subpacket->write(out);
}
