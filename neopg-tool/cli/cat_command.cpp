/* NeoPG
   Copyright 2017 The NeoPG developers

   NeoPG is released under the Simplified BSD License (see license.txt)
*/

#include <iostream>

#include <botan/filters.h>

#include <neopg-tool/cli/cat_command.h>

namespace NeoPG {

void CatCommand::run() {
  Botan::Pipe pipe(new Botan::DataSink_Stream(std::cout));

  if (m_files.empty()) m_files.emplace_back("-");

  for (auto& file : m_files) {
    if (file == "-") {
      Botan::DataSource_Stream in{std::cin};
      pipe.process_msg(in);
    } else {
      Botan::DataSource_Stream in{file, true};
      pipe.process_msg(in);
    }
  }
}

}  // Namespace NeoPG
