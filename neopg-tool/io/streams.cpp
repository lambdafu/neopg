/* NeoPG
   Copyright 2017 The NeoPG developers

   NeoPG is released under the Simplified BSD License (see license.txt)
*/

#include <neopg-tool/io/streams.h>

namespace NeoPG {

/* True iff stdin/stdout are not claimed yet.  */
static bool s_stdio_available{true};
/* The object that claimed stdin/stdout.  */
static std::string s_stdio_user;

bool Streams::PotentialStdioUser::ensure() {
  if (m_in && m_out)
    return true;
  else if (m_has_stdio)
    return true;
  else if (s_stdio_available) {
    s_stdio_available = false;
    s_stdio_user = m_name;
    m_has_stdio = true;
    return true;
  } else
    // FIXME: Use format function and translation.
    throw std::runtime_error("I/O not available for " + m_name +
                             " (blocked by " + s_stdio_user + ")");
}

std::istream& Streams::PotentialStdioUser::in() {
  ensure();
  if (m_in)
    return *m_in.get();
  else
    return std::cin;
}

std::ostream& Streams::PotentialStdioUser::out() {
  ensure();
  if (m_out)
    return *m_out.get();
  else
    return std::cout;
}

void Streams::reset() {
  s_stdio_available = true;
  s_stdio_user.clear();
  m_data.m_has_stdio = false;
  m_console.m_has_stdio = false;
}
/* Singleton */
Streams streams;

}  // namespace NeoPG
