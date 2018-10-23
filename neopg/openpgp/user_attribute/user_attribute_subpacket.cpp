// OpenPGP user attribute subpacket (implementation)
// Copyright 2017-2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/user_attribute/user_attribute_subpacket.h>

#include <neopg/openpgp/user_attribute/subpacket/image_attribute_subpacket.h>
#include <neopg/openpgp/user_attribute/subpacket/raw_user_attribute_subpacket.h>

#include <neopg/utils/stream.h>

using namespace NeoPG;

void UserAttributeSubpacketLength::verify_length(
    uint32_t length, UserAttributeSubpacketLengthType length_type) {
  if (length_type == UserAttributeSubpacketLengthType::OneOctet and
      not(length <= 0xbf)) {
    throw std::logic_error("Invalid packet length for one octet");
  } else if (length_type == UserAttributeSubpacketLengthType::TwoOctet and
             not(length >= 0xc0 and length <= 0x3fbf)) {
    throw std::logic_error("Invalid packet length for two octets");
  }
}

UserAttributeSubpacketLengthType UserAttributeSubpacketLength::best_length_type(
    uint32_t length) {
  if (length <= 0xbf)
    return UserAttributeSubpacketLengthType::OneOctet;
  else if (length <= 0x3fbf)
    return UserAttributeSubpacketLengthType::TwoOctet;
  else
    return UserAttributeSubpacketLengthType::FiveOctet;
}

void UserAttributeSubpacketLength::set_length(
    uint32_t length, UserAttributeSubpacketLengthType length_type) {
  verify_length(length, length_type);
  m_length_type = length_type;
  m_length = length;
}

UserAttributeSubpacketLength::UserAttributeSubpacketLength(
    uint32_t length, UserAttributeSubpacketLengthType length_type) {
  set_length(length, length_type);
}

void UserAttributeSubpacketLength::write(std::ostream& out) {
  UserAttributeSubpacketLengthType lentype = m_length_type;
  if (lentype == UserAttributeSubpacketLengthType::Default)
    lentype = best_length_type(m_length);

  switch (lentype) {
    case UserAttributeSubpacketLengthType::OneOctet:
      out << (uint8_t)m_length;
      break;

    case UserAttributeSubpacketLengthType::TwoOctet: {
      uint32_t adj_length = m_length - 0xc0;
      out << (uint8_t)(((adj_length >> 8) & 0x3f) + 0xc0)
          << ((uint8_t)(adj_length & 0xff));
    } break;

    case UserAttributeSubpacketLengthType::FiveOctet:
      out << (uint8_t)0xff << ((uint8_t)((m_length >> 24) & 0xff))
          << ((uint8_t)((m_length >> 16) & 0xff))
          << ((uint8_t)((m_length >> 8) & 0xff))
          << ((uint8_t)(m_length & 0xff));
      break;

    // LCOV_EXCL_START
    case UserAttributeSubpacketLengthType::Default:
      throw std::logic_error(
          "Unspecific user attribute subpacket length type (shouldn't "
          "happen).");
      // LCOV_EXCL_STOP
  }
}

std::unique_ptr<UserAttributeSubpacket> UserAttributeSubpacket::create_or_throw(
    UserAttributeSubpacketType type, ParserInput& in) {
  switch (type) {
    case UserAttributeSubpacketType::Image:
      return ImageAttributeSubpacket::create_or_throw(in);
    default:
      return RawUserAttributeSubpacket::create_or_throw(type, in);
  }
}

void UserAttributeSubpacket::write(
    std::ostream& out, UserAttributeSubpacketLengthType length_type) const {
  if (m_length) {
    m_length->write(out);
  } else {
    CountingStream cnt;
    write_body(cnt);
    uint32_t len = cnt.bytes_written();
    // Length needs to include the type octet.
    if (len == (uint32_t)-1)
      throw std::length_error("user attribute subpacket too large");
    len = len + 1;
    UserAttributeSubpacketLength default_length(len, length_type);
    default_length.write(out);
  }
  auto subpacket_type = static_cast<uint8_t>(type());
  out << subpacket_type;
  write_body(out);
}

uint32_t UserAttributeSubpacket::body_length() const {
  CountingStream cnt;
  write_body(cnt);
  return cnt.bytes_written();
}
