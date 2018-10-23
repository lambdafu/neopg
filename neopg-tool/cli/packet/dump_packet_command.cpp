// NeoPG
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg-tool/cli/packet/dump_packet_command.h>

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
