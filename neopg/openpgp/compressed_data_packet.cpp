// OpenPGP compressed data packet (implementation)
// Copyright 2017-2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/compressed_data_packet.h>
#include <neopg/openpgp/packet_header.h>
#include <neopg/utils/stream.h>

namespace NeoPG {

void CompressedDataPacket::write_body(std::ostream& out) const {
  out << (uint8_t)compression_algorithm();
  write_compressed_data(out);
}

PacketType CompressedDataPacket::type() const {
  return PacketType::CompressedData;
}

/* Uncompressed Data Packet */

void UncompressedDataPacket::write_compressed_data(std::ostream& out) const {
  out.write((char*)m_data.data(), m_data.size());
}

CompressionAlgorithm UncompressedDataPacket::compression_algorithm() const {
  return CompressionAlgorithm::Uncompressed;
}

/* Deflate Compressed Data Packet */

void DeflateCompressedDataPacket::write_compressed_data(
    std::ostream& out) const {
  out.write((char*)m_data.data(), m_data.size());
}

CompressionAlgorithm DeflateCompressedDataPacket::compression_algorithm()
    const {
  return CompressionAlgorithm::Deflate;
}

/* Zlib Compressed Data Packet */

void ZlibCompressedDataPacket::write_compressed_data(std::ostream& out) const {
  out.write((char*)m_data.data(), m_data.size());
}

CompressionAlgorithm ZlibCompressedDataPacket::compression_algorithm() const {
  return CompressionAlgorithm::Zlib;
}

/* Bzip2 Compressed Data Packet */

void Bzip2CompressedDataPacket::write_compressed_data(std::ostream& out) const {
  out.write((char*)m_data.data(), m_data.size());
}

CompressionAlgorithm Bzip2CompressedDataPacket::compression_algorithm() const {
  return CompressionAlgorithm::Bzip2;
}

}  // namespace NeoPG
