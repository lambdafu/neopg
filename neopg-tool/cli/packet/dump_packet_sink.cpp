// dump packet sink (implementation)
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg-tool/cli/packet/dump_packet_sink.h>

#include <neopg-tool/cli/packet/dump/legacy_dump.h>

#include <neopg/openpgp/public_key/data/v3_public_key_data.h>
#include <neopg/openpgp/public_key/data/v4_public_key_data.h>

#include <neopg/openpgp/public_key/material/dsa_public_key_material.h>
#include <neopg/openpgp/public_key/material/ecdh_public_key_material.h>
#include <neopg/openpgp/public_key/material/ecdsa_public_key_material.h>
#include <neopg/openpgp/public_key/material/eddsa_public_key_material.h>
#include <neopg/openpgp/public_key/material/elgamal_public_key_material.h>
#include <neopg/openpgp/public_key/material/raw_public_key_material.h>
#include <neopg/openpgp/public_key/material/rsa_public_key_material.h>

#include <neopg/openpgp/public_key/material/dsa_public_key_material.h>
#include <neopg/openpgp/public_key/material/ecdh_public_key_material.h>
#include <neopg/openpgp/public_key/material/ecdsa_public_key_material.h>
#include <neopg/openpgp/public_key/material/eddsa_public_key_material.h>
#include <neopg/openpgp/public_key/material/elgamal_public_key_material.h>
#include <neopg/openpgp/public_key/material/rsa_public_key_material.h>

#include <neopg/openpgp/signature/data/v3_signature_data.h>
#include <neopg/openpgp/signature/data/v4_signature_data.h>

#include <neopg/openpgp/signature/subpacket/embedded_signature_subpacket.h>
#include <neopg/openpgp/signature/subpacket/exportable_certification_subpacket.h>
#include <neopg/openpgp/signature/subpacket/features_subpacket.h>
#include <neopg/openpgp/signature/subpacket/issuer_subpacket.h>
#include <neopg/openpgp/signature/subpacket/key_expiration_time_subpacket.h>
#include <neopg/openpgp/signature/subpacket/key_flags_subpacket.h>
#include <neopg/openpgp/signature/subpacket/key_server_preferences_subpacket.h>
#include <neopg/openpgp/signature/subpacket/notation_data_subpacket.h>
#include <neopg/openpgp/signature/subpacket/policy_uri_subpacket.h>
#include <neopg/openpgp/signature/subpacket/preferred_compression_algorithms_subpacket.h>
#include <neopg/openpgp/signature/subpacket/preferred_hash_algorithms_subpacket.h>
#include <neopg/openpgp/signature/subpacket/preferred_key_server_subpacket.h>
#include <neopg/openpgp/signature/subpacket/preferred_symmetric_algorithms_subpacket.h>
#include <neopg/openpgp/signature/subpacket/primary_user_id_subpacket.h>
#include <neopg/openpgp/signature/subpacket/reason_for_revocation_subpacket.h>
#include <neopg/openpgp/signature/subpacket/regular_expression_subpacket.h>
#include <neopg/openpgp/signature/subpacket/revocable_subpacket.h>
#include <neopg/openpgp/signature/subpacket/revocation_key_subpacket.h>
#include <neopg/openpgp/signature/subpacket/signature_creation_time_subpacket.h>
#include <neopg/openpgp/signature/subpacket/signature_expiration_time_subpacket.h>
#include <neopg/openpgp/signature/subpacket/signature_target_subpacket.h>
#include <neopg/openpgp/signature/subpacket/signers_user_id_subpacket.h>
#include <neopg/openpgp/signature/subpacket/trust_signature_subpacket.h>

#include <neopg/openpgp/signature/material/dsa_signature_material.h>
#include <neopg/openpgp/signature/material/ecdsa_signature_material.h>
#include <neopg/openpgp/signature/material/eddsa_signature_material.h>
#include <neopg/openpgp/signature/material/raw_signature_material.h>
#include <neopg/openpgp/signature/material/rsa_signature_material.h>

#include <neopg/openpgp/user_attribute/subpacket/image_attribute_subpacket.h>

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
