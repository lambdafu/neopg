/* Command line parsing
   Copyright 2017 The NeoPG developers

   NeoPG is released under the Simplified BSD License (see license.txt)
*/

#pragma once

#include <neopg-tool/command.h>
#include <neopg-tool/dump_packet_command.h>

namespace NeoPG {

class MarkerPacketCommand : public Command {
 public:
  MarkerPacketCommand(CLI::App& app, const std::string& flag,
                      const std::string& description,
                      const std::string& group_name = "")
      : Command(app, flag, description, group_name) {}
  void run();
};

class UserIdPacketCommand : public Command {
 public:
  std::string m_uid;

  UserIdPacketCommand(CLI::App& app, const std::string& flag,
                      const std::string& description,
                      const std::string& group_name = "")
      : Command(app, flag, description, group_name) {
    m_cmd.add_option("data", m_uid, "user ID data");
  }

  void run();
};

class FilterPacketCommand : public Command {
 public:
  std::vector<std::string> m_files;

  FilterPacketCommand(CLI::App& app, const std::string& flag,
                      const std::string& description,
                      const std::string& group_name = "")
      : Command(app, flag, description, group_name) {
    m_cmd.add_option("file", m_files, "file to process");
  }
  void run();
};

class PacketCommand : public Command {
 public:
  const std::string group_write = "Write packet";
  const std::string group_process = "Process packet";

  MarkerPacketCommand cmd_marker;
  UserIdPacketCommand cmd_uid;
  FilterPacketCommand cmd_filter;
  DumpPacketCommand cmd_dump;

  virtual void run();

  PacketCommand(CLI::App& app, const std::string& flag,
                const std::string& description,
                const std::string& group_name = "");

  virtual ~PacketCommand() {}
};

}  // Namespace NeoPG
