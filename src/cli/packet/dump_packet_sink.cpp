// dump packet sink (implementation)
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg-tool/dump_packet_sink.h>

#include <neopg-tool/legacy_dump.h>

#include <neopg/v3_public_key_data.h>
#include <neopg/v4_public_key_data.h>

#include <neopg/dsa_public_key_material.h>
#include <neopg/ecdh_public_key_material.h>
#include <neopg/ecdsa_public_key_material.h>
#include <neopg/eddsa_public_key_material.h>
#include <neopg/elgamal_public_key_material.h>
#include <neopg/raw_public_key_material.h>
#include <neopg/rsa_public_key_material.h>

#include <neopg/dsa_public_key_material.h>
#include <neopg/ecdh_public_key_material.h>
#include <neopg/ecdsa_public_key_material.h>
#include <neopg/eddsa_public_key_material.h>
#include <neopg/elgamal_public_key_material.h>
#include <neopg/rsa_public_key_material.h>

#include <neopg/v3_signature_data.h>
#include <neopg/v4_signature_data.h>

#include <neopg/embedded_signature_subpacket.h>
#include <neopg/exportable_certification_subpacket.h>
#include <neopg/features_subpacket.h>
#include <neopg/issuer_subpacket.h>
#include <neopg/key_expiration_time_subpacket.h>
#include <neopg/key_flags_subpacket.h>
#include <neopg/key_server_preferences_subpacket.h>
#include <neopg/notation_data_subpacket.h>
#include <neopg/policy_uri_subpacket.h>
#include <neopg/preferred_compression_algorithms_subpacket.h>
#include <neopg/preferred_hash_algorithms_subpacket.h>
#include <neopg/preferred_key_server_subpacket.h>
#include <neopg/preferred_symmetric_algorithms_subpacket.h>
#include <neopg/primary_user_id_subpacket.h>
#include <neopg/reason_for_revocation_subpacket.h>
#include <neopg/regular_expression_subpacket.h>
#include <neopg/revocable_subpacket.h>
#include <neopg/revocation_key_subpacket.h>
#include <neopg/signature_creation_time_subpacket.h>
#include <neopg/signature_expiration_time_subpacket.h>
#include <neopg/signature_target_subpacket.h>
#include <neopg/signers_user_id_subpacket.h>
#include <neopg/trust_signature_subpacket.h>

#include <neopg/dsa_signature_material.h>
#include <neopg/ecdsa_signature_material.h>
#include <neopg/eddsa_signature_material.h>
#include <neopg/raw_signature_material.h>
#include <neopg/rsa_signature_material.h>

#include <neopg/image_attribute_subpacket.h>

#include <botan/data_snk.h>
#include <botan/data_src.h>
#include <botan/hex.h>

#include <botan/ber_dec.h>
#include <botan/oids.h>

#include <CLI11.hpp>

#include <spdlog/fmt/fmt.h>

#include <rang.hpp>

#include <tao/json.hpp>

#include <iostream>

using namespace NeoPG;

void DumpPacketSink::dump(const Packet* packet) const {
  switch (packet->type()) {
    case PacketType::Marker: {
      auto pkt = dynamic_cast<const MarkerPacket*>(packet);
      assert(pkt != nullptr);
      dump(pkt);
      break;
    }
    case PacketType::UserId: {
      auto pkt = dynamic_cast<const UserIdPacket*>(packet);
      assert(pkt != nullptr);
      dump(pkt);
      break;
    }
    case PacketType::UserAttribute: {
      auto pkt = dynamic_cast<const UserAttributePacket*>(packet);
      assert(pkt != nullptr);
      dump(pkt);
      break;
    }

    case PacketType::PublicKey: {
      auto pkt = dynamic_cast<const PublicKeyPacket*>(packet);
      assert(pkt != nullptr);
      dump(pkt);
      break;
    }

    case PacketType::PublicSubkey: {
      auto pkt = dynamic_cast<const PublicSubkeyPacket*>(packet);
      assert(pkt != nullptr);
      dump(pkt);
      break;
    }

    case PacketType::Signature: {
      auto pkt = dynamic_cast<const SignaturePacket*>(packet);
      assert(pkt != nullptr);
      dump(pkt);
      break;
    }
    default:
      break;
  }
}
// catch (ParserError& exc) {
//   exc.m_pos.m_byte += offset;
//   std::cout << rang::style::bold << rang::fgB::red << "ERROR"
//             << rang::style::reset << ":" << exc.as_string() <<
//             "\n";
// }
//
//   void error_packet(std::unique_ptr<PacketHeader> header,
//                     std::unique_ptr<ParserError> exc) {
//     output_header(std::cout, header.get());
//     std::cout << rang::style::bold << rang::fgB::red << "ERROR"
//               << rang::style::reset << ":" << exc->as_string() <<
//               "\n";
//   };
// };

void DumpPacketSink::next_packet(std::unique_ptr<PacketHeader> header,
                                 const char* data, size_t length) {
  assert(length == header->length());
  size_t offset = header->m_offset;
  try {
    ParserInput in{data, length};
    auto packet = Packet::create_or_throw(header->type(), in);
    packet->m_header = std::move(header);
    dump(packet.get());
  } catch (ParserError& exc) {
    exc.m_pos.m_byte += offset;
    std::cerr << rang::style::bold << rang::fgB::red << "ERROR"
              << rang::style::reset << ":" << exc.as_string() << "\n";
    // FIXME: Add option to suppress errorneous output.
    // header->write(std::cout);
    // std::cout.write(data, length);
  }
}
void DumpPacketSink::start_packet(std::unique_ptr<PacketHeader> header) {}
void DumpPacketSink::continue_packet(
    std::unique_ptr<NewPacketLength> length_info, const char* data,
    size_t length) {}
void DumpPacketSink::finish_packet(std::unique_ptr<NewPacketLength> length_info,
                                   const char* data, size_t length) {}
void DumpPacketSink::error_packet(std::unique_ptr<PacketHeader> header,
                                  std::unique_ptr<ParserError> exc) {
  std::cerr << rang::style::bold << rang::fgB::red << "ERROR"
            << rang::style::reset << ":" << exc->as_string() << "\n";
}
