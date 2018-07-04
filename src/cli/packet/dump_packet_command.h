// neopg packet dump
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#pragma once

#include <neopg-tool/command.h>

#include <neopg/openpgp.h>

#include <ostream>

namespace NeoPG {

class DumpPacketCommand : public Command {
 public:
  std::vector<std::string> m_files;
  std::string m_format;

  DumpPacketCommand(CLI::App& app, const std::string& flag,
                    const std::string& description,
                    const std::string& group_name = "")
      : Command(app, flag, description, group_name) {
    m_cmd.add_option("--format", m_format, "output format", true);
    m_cmd.add_option("file", m_files, "file to process");
  }
  void run();
};

}  // Namespace NeoPG
