// legacy dump format
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#pragma once

#include <neopg-tool/dump_packet_sink.h>

namespace NeoPG {

/// Legacy dump format like GnuPG.
class LegacyDump : public DumpPacketSink {
 public:
  /// Dispatcher.
  virtual void dump(const Packet* packet) const;

  virtual void dump(const MarkerPacket* packet) const;
  virtual void dump(const UserIdPacket* packet) const;
  virtual void dump(const UserAttributePacket* packet) const;
  virtual void dump(const PublicKeyPacket* packet) const;
  virtual void dump(const PublicSubkeyPacket* packet) const;
  virtual void dump(const SignaturePacket* packet) const;

  LegacyDump(std::ostream& out) : DumpPacketSink(out) {}
};

}  // Namespace NeoPG
