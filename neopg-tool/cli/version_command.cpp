/* NeoPG
   Copyright 2017 The NeoPG developers

   NeoPG is released under the Simplified BSD License (see license.txt)
*/

#include <iostream>

#include <neopg-tool/version.h>
#include <neopg-tool/cli/version_command.h>

namespace NeoPG {

void VersionCommand::run() { std::cout << "NeoPG " << NEOPG_VERSION << "\n"; }

}  // Namespace NeoPG
