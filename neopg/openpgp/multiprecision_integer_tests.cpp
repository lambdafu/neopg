// OpenPGP multiprecision integer (tests)
// Copyright 2017-2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/multiprecision_integer.h>

#include <gtest/gtest.h>

#include <memory>
#include <sstream>

using namespace NeoPG;

TEST(NeopgTest, openpgp_multiprecision_integer_test) {
  {
    std::stringstream out;
    MultiprecisionInteger mpi;
    mpi.m_length = 1;
    mpi.m_bits.assign({0x01});
    mpi.write(out);
    ASSERT_EQ(out.str(), std::string("\x00\x01\x01", 3));
  }

  {
    std::stringstream out;
    MultiprecisionInteger mpi(0x16234);
    ASSERT_EQ(mpi.m_length, 17);
    ASSERT_EQ(mpi.m_bits, std::vector<uint8_t>({0x01, 0x62, 0x34}));
    mpi.write(out);
    ASSERT_EQ(out.str(), std::string("\x00\x11\x01\x62\x34", 5));
  }
}
