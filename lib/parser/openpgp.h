// OpenPGP parser
// Copyright 2017-2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#pragma once

#include <neopg/parser_error.h>
#include <neopg/raw_packet.h>

#include <botan/data_snk.h>
#include <botan/data_src.h>

namespace NeoPG {

class NEOPG_UNSTABLE_API RawPacketSink {
 public:
  // Takes ownership of HEADER.  Data is passed by reference and only valid
  // during execution of this function.
  virtual void next_packet(std::unique_ptr<PacketHeader> header,
                           const char* data, size_t length) = 0;

  // Takes ownership of HEADER.  The data follows with continue_packet calls.
  virtual void start_packet(std::unique_ptr<PacketHeader> header) = 0;

  // Called after start_packet. Data is passed by
  // reference and only valid during execution of this function.  If length_info
  // is nullptr, then this is either an old header indeterminate length packet,
  // or the first new header partial data after start_packet.
  virtual void continue_packet(std::unique_ptr<NewPacketLength> length_info,
                               const char* data, size_t length) = 0;

  // Called eventually after start_packet and zero or more continue_packet
  // calls.  The LENGTH_INFO allows to reconstruct the original binary stream
  // (only valid for new packet format).
  virtual void finish_packet(std::unique_ptr<NewPacketLength> length_info,
                             const char* data, size_t length) = 0;

  // Error while parsing a packet (usually if a packet is too large for the
  // input buffer, or if the final packet is truncated). The packet content is
  // skipped, and processing can continue. Takes ownership of HEADER.
  virtual void error_packet(std::unique_ptr<PacketHeader> header,
                            std::unique_ptr<ParserError> error) = 0;

  // Prevent memory leak when upcasting in smart pointer containers.
  virtual ~RawPacketSink() = default;
};

class NEOPG_UNSTABLE_API RawPacketParser {
  RawPacketSink& m_sink;

 public:
  // This must be at least as many bytes as the parser needs to see between two
  // discard rules.
  // This is dominated by variable length fields and partial data packets.
  // OpenPGP does not impose limits on fields such as the user ID, so we have
  // our own limits, see the NeoPG OpenPGP profile. Post-quantum cryptography
  // will require some large key packets, so this limit will go up eventually.
  // For partial length data packets, GnuPG emits at most 8KiB.
  // Photo ids can be much larger.
  static const size_t MAX_PARSER_BUFFER = 4 * 1024 * 1024;  // 4 MiB

  RawPacketParser(RawPacketSink& sink) : m_sink(sink) {}

  void process(Botan::DataSource& source);
  void process(std::istream& source);
  void process(const std::string& source);
};

}  // namespace NeoPG
