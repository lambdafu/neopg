/* Command line parsing
   Copyright 2017 The NeoPG developers

   NeoPG is released under the Simplified BSD License (see license.txt)
*/

#pragma once

#include <iostream>
#include <memory>

namespace NeoPG {

class Streams {
 public:
  /* We keep track of std::cin and std::cout use.  The two can only be claimed
     as a pair, and only once during in each invocation.
     Frankly, we are providing this for legacy compatibility, because GnuPG
     supports a pipe mode of operation where data is streamed through the
     process via stdin and stdout, and the passphrase can still be provided
     at the console.  There are many limitations to this approach, and
     file-based operations are strongly preferred.  */

  struct PotentialStdioUser {
    const std::string m_name;
    bool m_has_stdio{false};
    std::unique_ptr<std::istream> m_in;
    std::unique_ptr<std::ostream> m_out;

    PotentialStdioUser(const std::string& name) : m_name(name) {}

    bool ensure();
    std::istream& in();
    std::ostream& out();
  };

  PotentialStdioUser m_data{"data"};
  PotentialStdioUser m_console{"console"};

  /* Reset stdio user.  This interface is used in testing.  */
  void reset();

  /* Raw logging stream.  Defaults to std::cerr.  Used by the logging interface.
   */
  std::unique_ptr<std::ostream> m_log_out;
};

/* Singleton.  */
extern Streams streams;

}  // Namespace NeoPG
