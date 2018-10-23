/* Stream functions
   Copyright 2017 The NeoPG developers

   NeoPG is released under the Simplified BSD License (see license.txt)
*/

#include <neopg/utils/stream.h>

namespace NeoPG {

uint32_t CountingStreamBuf::bytes_written() { return m_bytes_written; }

std::streamsize CountingStreamBuf::xsputn(const char_type* s,
                                          std::streamsize n) {
  m_bytes_written += n;
  return n;
};

CountingStream::int_type CountingStreamBuf::overflow(
    CountingStream::int_type ch) {
  m_bytes_written++;
  return 1;
}

CountingStream::CountingStream()
    : std::ios(0), std::ostream(&m_counting_stream_buf) {}

uint32_t CountingStream::bytes_written() {
  return m_counting_stream_buf.bytes_written();
}

}  // namespace NeoPG
