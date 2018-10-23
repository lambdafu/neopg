// OpenPGP packet header (implementation)
// Copyright 2017-2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/packet_header.h>

#include <neopg/intern/cplusplus.h>

namespace NeoPG {

std::unique_ptr<OldPacketHeader> OldPacketHeader::create_or_throw(
    PacketType type, uint32_t length) {
  return NeoPG::make_unique<OldPacketHeader>(type, length);
}

void OldPacketHeader::verify_length(uint32_t length,
                                    PacketLengthType length_type) {
  if (length_type == PacketLengthType::OneOctet and length > 0xff)
    throw std::logic_error("Invalid packet length for one octet");
  if (length_type == PacketLengthType::TwoOctet and length > 0xffff)
    throw std::logic_error("Invalid packet length for two octets");
}

PacketLengthType OldPacketHeader::best_length_type(uint32_t length) {
  if (length <= 0xff)
    return PacketLengthType::OneOctet;
  else if (length <= 0xffff)
    return PacketLengthType::TwoOctet;
  else
    return PacketLengthType::FourOctet;
}

OldPacketHeader::OldPacketHeader(PacketType packet_type, uint32_t length,
                                 PacketLengthType length_type) {
  set_packet_type(packet_type);
  set_length(length, length_type);
}

void OldPacketHeader::set_packet_type(PacketType packet_type) {
  if ((uint8_t)packet_type >= 16) throw std::logic_error("Invalid tag");
  m_packet_type = packet_type;
}

void OldPacketHeader::set_length(uint32_t length,
                                 PacketLengthType length_type) {
  verify_length(length, length_type);
  m_length_type = length_type;
  m_length = length;
}

void OldPacketHeader::write(std::ostream& out) const {
  PacketLengthType lentype = m_length_type;
  if (lentype == PacketLengthType::Default)
    lentype = best_length_type(m_length);

  uint8_t tag = 0x80 | ((uint8_t)m_packet_type << 2);
  switch (lentype) {
    case PacketLengthType::OneOctet:
      out << (uint8_t)(tag | 0x00) << ((uint8_t)(m_length & 0xff));
      break;

    case PacketLengthType::TwoOctet:
      out << (uint8_t)(tag | 0x01) << ((uint8_t)((m_length >> 8) & 0xff))
          << ((uint8_t)(m_length & 0xff));
      break;

    case PacketLengthType::FourOctet:
      out << (uint8_t)(tag | 0x02) << ((uint8_t)((m_length >> 24) & 0xff))
          << ((uint8_t)((m_length >> 16) & 0xff))
          << ((uint8_t)((m_length >> 8) & 0xff))
          << ((uint8_t)(m_length & 0xff));
      break;

    case PacketLengthType::Indeterminate:
      out << (uint8_t)(tag | 0x03);
      break;

    // LCOV_EXCL_START
    case PacketLengthType::Default:
      throw std::logic_error(
          "Unspecific packet length type (shouldn't happen).");
      // LCOV_EXCL_STOP
  }
}

std::unique_ptr<NewPacketHeader> NewPacketHeader::create_or_throw(
    PacketType type, uint32_t length) {
  return NeoPG::make_unique<NewPacketHeader>(type, length);
}

void NewPacketTag::set_packet_type(PacketType packet_type) {
  if ((uint8_t)packet_type >= 64) throw std::logic_error("Invalid tag");
  m_packet_type = packet_type;
}

NewPacketTag::NewPacketTag(PacketType packet_type) {
  set_packet_type(packet_type);
}

void NewPacketTag::write(std::ostream& out) const {
  uint8_t tag = 0x80 | 0x40 | (uint8_t)m_packet_type;
  out << (uint8_t)tag;
}

void NewPacketLength::verify_length(uint32_t length,
                                    PacketLengthType length_type) {
  if (length_type == PacketLengthType::OneOctet and not(length <= 0xbf)) {
    throw std::logic_error("Invalid packet length for one octet");
  } else if (length_type == PacketLengthType::TwoOctet and
             not(length >= 0xc0 and length <= 0x20bf)) {
    throw std::logic_error("Invalid packet length for two octets");
  } else if (length_type == PacketLengthType::Partial and
             not(length != 0 and length == (1U << __builtin_ctz(length)) and
                 length != (1U << 31))) {
    throw std::logic_error("Invalid indeterminate packet length");
  }
}

PacketLengthType NewPacketLength::best_length_type(uint32_t length) {
  if (length <= 0xbf)
    return PacketLengthType::OneOctet;
  else if (length <= 0x20bf)
    return PacketLengthType::TwoOctet;
  else
    return PacketLengthType::FiveOctet;
}

void NewPacketLength::set_length(uint32_t length, PacketLengthType length_type)

{
  verify_length(length, length_type);
  m_length_type = length_type;
  m_length = length;
}

NewPacketLength::NewPacketLength(uint32_t length,
                                 PacketLengthType length_type) {
  set_length(length, length_type);
}

void NewPacketLength::write(std::ostream& out) const {
  PacketLengthType lentype = m_length_type;
  if (lentype == PacketLengthType::Default)
    lentype = best_length_type(m_length);

  switch (lentype) {
    case PacketLengthType::OneOctet:
      out << (uint8_t)m_length;
      break;

    case PacketLengthType::TwoOctet: {
      uint32_t adj_length = m_length - 192;
      out << (uint8_t)(((adj_length >> 8) & 0x1f) + 0xc0)
          << ((uint8_t)(adj_length & 0xff));
    } break;

    case PacketLengthType::FourOctet:
      out << (uint8_t)0xff << ((uint8_t)((m_length >> 24) & 0xff))
          << ((uint8_t)((m_length >> 16) & 0xff))
          << ((uint8_t)((m_length >> 8) & 0xff))
          << ((uint8_t)(m_length & 0xff));
      break;

    case PacketLengthType::Partial: {
      uint8_t exp = __builtin_ctz(m_length);
      out << (uint8_t)((exp & 0x1f) + 0xe0);
    } break;
    // LCOV_EXCL_START
    case PacketLengthType::Default:
      throw std::logic_error(
          "Unspecific packet length type (shouldn't happen).");
      // LCOV_EXCL_STOP
  }
}

void NewPacketHeader::write(std::ostream& out) const {
  m_tag.write(out);
  m_length.write(out);
}

}  // namespace NeoPG
