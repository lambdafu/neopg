/* NeoPG
   Copyright 2017 The NeoPG developers

   NeoPG is released under the Simplified BSD License (see license.txt)
*/

#include <iostream>

#include <botan/filters.h>

#include <neopg-tool/cli/armor_command.h>

namespace NeoPG {

void ArmorCommand::encode() {
  bool has_title = !m_title.empty();

  if (m_files.empty()) m_files.emplace_back("-");

  for (auto& file : m_files) {
    Botan::Filter* sink = (file == "-")
                              ? new Botan::DataSink_Stream(std::cout)
                              : new Botan::DataSink_Stream(file + ".asc", true);

    const int PGP_WIDTH{64};
    Botan::Pipe pipe(new Botan::Fork(
        new Botan::Chain(new Botan::Base64_Encoder(true, PGP_WIDTH), sink),
        new Botan::Chain(new Botan::Hash_Filter("CRC24"),
                         new Botan::Base64_Encoder())));

    if (has_title) {
      std::stringstream header_;
      header_ << "-----BEGIN " << m_title << "-----\n\n";
      const auto header = header_.str();
      sink->write((uint8_t*)header.data(), header.size());
    }

    if (file == "-") {
      Botan::DataSource_Stream in{std::cin};
      pipe.process_msg(in);
    } else {
      Botan::DataSource_Stream in{file, true};
      pipe.process_msg(in);
    }

    if (m_crc24) {
      std::stringstream crc_;
      crc_ << "=" << pipe.read_all_as_string(1) << "\n";
      const auto crc = crc_.str();
      sink->write((uint8_t*)crc.data(), crc.size());
    }

    if (has_title) {
      std::stringstream footer_;
      footer_ << "-----END " << m_title << "-----\n";
      const auto footer = footer_.str();
      sink->write((uint8_t*)footer.data(), footer.size());
    }
  }
}

void ArmorCommand::decode() {
  // TODO
}

void ArmorCommand::run() {
  if (m_decode)
    decode();
  else
    encode();
}

}  // Namespace NeoPG
