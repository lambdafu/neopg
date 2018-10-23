// OpenPGP compressed data packet (implementation)
// Copyright 2017-2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#pragma once

#include <neopg/openpgp/packet.h>

#include <vector>

namespace NeoPG {

enum class NEOPG_UNSTABLE_API CompressionAlgorithm : uint8_t {
  Uncompressed = 0x00,
  Deflate = 0x01,
  Zlib = 0x02,
  Bzip2 = 0x03,
  Private_100 = 0x64,
  Private_101 = 0x65,
  Private_102 = 0x66,
  Private_103 = 0x67,
  Private_104 = 0x68,
  Private_105 = 0x69,
  Private_106 = 0x6a,
  Private_107 = 0x6b,
  Private_108 = 0x6c,
  Private_109 = 0x6d,
  Private_110 = 0x6e,
};

struct NEOPG_UNSTABLE_API CompressedDataPacket : Packet {
  void write_body(std::ostream& out) const override;
  PacketType type() const override;

  virtual void write_compressed_data(std::ostream& out) const = 0;
  virtual CompressionAlgorithm compression_algorithm() const = 0;
};

/* Uncompressed Data Packet.  */

struct NEOPG_UNSTABLE_API UncompressedDataPacket : CompressedDataPacket {
  std::vector<uint8_t> m_data;
  void write_compressed_data(std::ostream& out) const override;
  CompressionAlgorithm compression_algorithm() const override;
};

/* Deflate Compressed Data Packet.  */

struct NEOPG_UNSTABLE_API DeflateCompressedDataPacket : CompressedDataPacket {
  std::vector<uint8_t> m_data;
  void write_compressed_data(std::ostream& out) const override;
  CompressionAlgorithm compression_algorithm() const override;
};

/* Zlib Compressed Data Packet.  */

struct NEOPG_UNSTABLE_API ZlibCompressedDataPacket : CompressedDataPacket {
  std::vector<uint8_t> m_data;
  void write_compressed_data(std::ostream& out) const override;
  CompressionAlgorithm compression_algorithm() const override;
};

/* Bzip2 Compressed Data Packet.  */

struct NEOPG_UNSTABLE_API Bzip2CompressedDataPacket : CompressedDataPacket {
  std::vector<uint8_t> m_data;
  void write_compressed_data(std::ostream& out) const override;
  CompressionAlgorithm compression_algorithm() const override;
};

}  // namespace NeoPG
