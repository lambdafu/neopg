// neopg packet dump
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#pragma once

#include <neopg/parser/openpgp.h>

#include <neopg/openpgp/marker_packet.h>
#include <neopg/openpgp/public_key_packet.h>
#include <neopg/openpgp/public_subkey_packet.h>
#include <neopg/openpgp/signature_packet.h>
#include <neopg/openpgp/user_attribute_packet.h>
#include <neopg/openpgp/user_id_packet.h>

#include <ostream>

namespace NeoPG {

class DumpPacketSink : public RawPacketSink {
 public:
  /// The out stream to write to.
  std::ostream& m_out;

  DumpPacketSink(std::ostream& out) : m_out{out} {}
  virtual ~DumpPacketSink() = default;

  /// Dispatcher.
  virtual void dump(const Packet* packet) const;

  /// Visitor pattern for packet dumpers.
  virtual void dump(const MarkerPacket* packet) const = 0;
  virtual void dump(const UserIdPacket* packet) const = 0;
  virtual void dump(const UserAttributePacket* packet) const = 0;
  virtual void dump(const PublicKeyPacket* packet) const = 0;
  virtual void dump(const PublicSubkeyPacket* packet) const = 0;
  virtual void dump(const SignaturePacket* packet) const = 0;

  // Implement interface of RawPacketSink.
  void next_packet(std::unique_ptr<PacketHeader> header, const char* data,
                   size_t length);
  void start_packet(std::unique_ptr<PacketHeader> header);
  void continue_packet(std::unique_ptr<NewPacketLength> length_info,
                       const char* data, size_t length);
  void finish_packet(std::unique_ptr<NewPacketLength> length_info,
                     const char* data, size_t length);
  void error_packet(std::unique_ptr<PacketHeader> header,
                    std::unique_ptr<ParserError> exc);
};

}  // Namespace NeoPG
