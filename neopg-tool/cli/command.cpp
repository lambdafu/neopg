/* NeoPG
   Copyright 2017 The NeoPG developers

   NeoPG is released under the Simplified BSD License (see license.txt)
*/

#include <iostream>

#include <neopg-tool/cli/command.h>

namespace NeoPG {

Command::Command(CLI::App& app, const std::string& flag,
                 const std::string& description, const std::string& group_name)
    : m_app(app), m_cmd(*app.add_subcommand(flag, description)) {
  m_cmd.set_callback([this]() { this->run(); });
  if (!group_name.empty()) m_cmd.group(group_name);
}

LegacyCommand::LegacyCommand(CLI::App& app, const main_fnc_t& main_fnc,
                             const std::string& flag,
                             const std::string& description,
                             const std::string& group_name)
    : Command(app, flag, description, group_name), m_main_fnc(main_fnc) {
  m_cmd.set_help_flag();
  m_cmd.prefix_command(true);
}

void LegacyCommand::run() {
  std::vector<char*> args = {(char*)m_cmd.get_name().c_str()};
  std::vector<std::string> remaining = m_cmd.remaining();
  for (auto& arg : remaining) {
    args.push_back(const_cast<char*>(arg.c_str()));
  }
  m_main_fnc(args.size(), args.data());
}

}  // Namespace NeoPG
