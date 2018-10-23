// NeoPG compress command
// Copyright 2017 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#pragma once

#include <neopg-tool/cli/command.h>

namespace NeoPG {

class ListCompressCommand : public Command {
 public:
  ListCompressCommand(CLI::App& app, const std::string& flag,
                      const std::string& description,
                      const std::string& group_name = "")
      : Command(app, flag, description, group_name) {}
  void run();
};

class CompressCommand : public Command {
 public:
  std::vector<std::string> m_files;
  std::string m_algo{"gz"};
  int m_level = 0;
  bool m_decode = false;
  const std::string group = "Commands";
  ListCompressCommand cmd_list;

  void run() override;
  CompressCommand(CLI::App& app, const std::string& flag,
                  const std::string& description,
                  const std::string& group_name = "")
      : Command(app, flag, description, group_name),
        cmd_list(m_cmd, "list", "list supported compression functions", group) {
    m_cmd.add_flag("-d,--decompress", m_decode,
                   "decompress already compressed data");
    m_cmd.add_option("file", m_files, "file to hash");
    m_cmd.add_option("--algo", m_algo, "compression function", true);
    m_cmd.add_option("--level", m_level, "compression level (0 default, 1-9)");
  }
};

}  // Namespace NeoPG
