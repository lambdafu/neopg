// NeoPG compress command (implementation)
// Copyright 2017 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg-tool/cli/compress_command.h>

#include <botan/comp_filter.h>
#include <botan/compression.h>
#include <botan/filters.h>

#include <iostream>
#include <map>

namespace NeoPG {

void ListCompressCommand::run() {
  std::cout << "Any Botan-compatible algorithm specifier can be used:\n\n";
#if defined(BOTAN_HAS_ZLIB)
  std::cout << "Zlib, zlib\n";
  std::cout << "Gzip, gzip, gz\n";
  std::cout << "Deflate, deflate\n";
#endif

#if defined(BOTAN_HAS_BZIP2)
  std::cout << "bzip2, bz2, Bzip2\n";
#endif

#if defined(BOTAN_HAS_LZMA)
  std::cout << "lzma, xz, LZMA";
#endif
}

static const std::map<std::string, std::string> algo_to_suffix = {
    {"Deflate_Compression", ".zip"},
    {"Zlib_Compression", ".zlib"},
    {"Gzip_Compression", ".gz"},
    {"Bzip2_Compression", ".bz2"},
    {"Lzma_Compression", ".xz"}};

void CompressCommand::run() {
  bool multi_files = false;

  if (!m_cmd.get_subcommands().empty()) return;

  if (m_files.empty()) m_files.emplace_back("-");

  std::unique_ptr<Botan::Compression_Algorithm> compressor{
      Botan::make_compressor(m_algo)};
  if (!compressor) throw Botan::Lookup_Error("Compression", m_algo, "");
  const std::string suffix(algo_to_suffix.at(compressor->name()));

  for (auto& file : m_files) {
    std::unique_ptr<Botan::DataSource_Stream> source{
        (file == "-") ? new Botan::DataSource_Stream{std::cin}
                      : new Botan::DataSource_Stream{file, true}};
    Botan::Filter* compress =
        m_decode
            ? (Botan::Filter*)new Botan::Decompression_Filter(m_algo)
            : (Botan::Filter*)new Botan::Compression_Filter(m_algo, m_level);
    Botan::Filter* sink = (file == "-")
                              ? new Botan::DataSink_Stream(std::cout)
                              : new Botan::DataSink_Stream(file + suffix, true);
    Botan::Pipe pipe{compress, sink};
    pipe.process_msg(*source);
  }
}

}  // Namespace NeoPG
