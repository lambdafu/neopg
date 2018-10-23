// Stream functions
// Copyright 2017 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#pragma once

#include <neopg/utils/common.h>
#include <iostream>
#include <streambuf>

namespace NeoPG {

class NEOPG_UNSTABLE_API CountingStreamBuf : public std::streambuf {
 public:
  uint32_t bytes_written();

 protected:
  std::streamsize xsputn(const char_type* s, std::streamsize n) override;
  int_type overflow(int_type ch) override;

 private:
  uint32_t m_bytes_written = 0;
};

class NEOPG_UNSTABLE_API CountingStream : public std::ostream {
 public:
  CountingStream();
  uint32_t bytes_written();

 private:
  CountingStreamBuf m_counting_stream_buf;
};

}  // namespace NeoPG
