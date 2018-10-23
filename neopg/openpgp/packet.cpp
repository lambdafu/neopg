// OpenPGP packet (implementation)
// Copyright 2017-2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/packet.h>

#include <neopg/openpgp/marker_packet.h>
#include <neopg/openpgp/public_key_packet.h>
#include <neopg/openpgp/public_subkey_packet.h>
#include <neopg/openpgp/raw_packet.h>
#include <neopg/openpgp/signature_packet.h>
#include <neopg/openpgp/user_attribute_packet.h>
#include <neopg/openpgp/user_id_packet.h>

#include <neopg/parser/parser_input.h>
#include <neopg/utils/stream.h>

#include <assert.h>
#include <neopg/intern/cplusplus.h>

#ifndef NDEBUG
#include <botan/hex.h>
#include <sstream>
#endif

using namespace NeoPG;

std::unique_ptr<Packet> Packet::create_or_throw(PacketType type,
                                                ParserInput& in) {
  std::unique_ptr<Packet> packet;
#ifndef NDEBUG
  std::string orig_data{in.current(), in.size()};
#endif

  switch (type) {
    case PacketType::Marker:
      packet = MarkerPacket::create_or_throw(in);
      break;
    case PacketType::UserId:
      packet = UserIdPacket::create_or_throw(in);
      break;
    case PacketType::PublicKey:
      packet = PublicKeyPacket::create_or_throw(in);
      break;
    case PacketType::PublicSubkey:
      packet = PublicSubkeyPacket::create_or_throw(in);
      break;
    case PacketType::Signature:
      packet = SignaturePacket::create_or_throw(in);
      break;
    case PacketType::UserAttribute:
      packet = UserAttributePacket::create_or_throw(in);
      break;
    default:
      // Should we do this?
      packet = NeoPG::make_unique<RawPacket>(
          type, std::string(in.current(), in.size()));
      break;
  }

#ifndef NDEBUG
  /// Output the packet data and verify that it outputs to
  /// exactly the same bytes as the original data.
  std::stringstream out;
  packet->write_body(out);
  // if (orig_data != out.str()) {
  //   std::cout << "ORIG: "
  //             << Botan::hex_encode((const uint8_t*)orig_data.data(),
  //                                  orig_data.size())
  //             << "\n";
  //   std::string o = out.str();
  //   std::cout << "PARS: "
  //             << Botan::hex_encode((const uint8_t*)o.data(), o.size()) <<
  //             "\n";
  // }
  assert(orig_data == out.str());
#endif
  return packet;
}

void Packet::write(std::ostream& out,
                   packet_header_factory header_factory) const {
  if (m_header) {
    m_header->write(out);
  } else {
    CountingStream cnt;
    write_body(cnt);
    uint32_t len = cnt.bytes_written();
    std::unique_ptr<PacketHeader> default_header = header_factory(type(), len);
    default_header->write(out);
  }
  write_body(out);
}
