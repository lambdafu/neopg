// NeoPG
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg-tool/dump_packet_command.h>

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

static void process_msg(Botan::DataSource& source, Botan::DataSink& out) {
  out.start_msg();
  // DumpPacketSink sink(std::cout);
  LegacyDump sink(std::cout);
  RawPacketParser parser(sink);

  try {
    parser.process(source);
  } catch (const ParserError& exc) {
    std::cout << rang::style::bold << rang::fgB::red << "ERROR"
              << rang::style::reset
              << ":unrecoverable error:" << exc.as_string() << "\n";
  }
  out.end_msg();
}

void DumpPacketCommand::run() {
  Botan::DataSink_Stream out{std::cout};

  if (m_files.empty()) m_files.emplace_back("-");
  for (auto& file : m_files) {
    if (file == "-") {
      Botan::DataSource_Stream in{std::cin};
      process_msg(in, out);
    } else {
      // Open in binary mode.
      Botan::DataSource_Stream in{file, true};
      process_msg(in, out);
    }
  }
}
