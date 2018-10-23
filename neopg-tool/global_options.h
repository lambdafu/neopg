// global_options.h
// Copyright 2017 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#pragma once

#include <iostream>

#include <spdlog/spdlog.h>
#include <CLI11.hpp>
#include <rang.hpp>

namespace rang {
std::istream& operator>>(std::istream& in, rang::control& when) {
  std::string label;
  in >> label;
  if (label == "always")
    when = rang::control::Force;
  else if (label == "never")
    when = rang::control::Off;
  else if (label == "auto")
    when = rang::control::Auto;
  else {
    // We are not pushing back what we couldn't parse.  Seems to be OK.
    in.setstate(std::ios_base::failbit);
  }
  return in;
}

std::ostream& operator<<(std::ostream& out, const rang::control& when) {
  switch (when) {
    case rang::control::Force:
      return out << "always";
    case rang::control::Off:
      return out << "never";
    default:
      return out << "auto";
  }
}
}  // namespace rang

namespace spdlog {
namespace level {
std::istream& operator>>(std::istream& in, spdlog::level::level_enum& level) {
  std::string label;
  in >> label;
  if (label == "trace")
    level = spdlog::level::trace;
  else if (label == "debug")
    level = spdlog::level::debug;
  else if (label == "info")
    level = spdlog::level::info;
  else if (label == "warning")
    level = spdlog::level::warn;
  else if (label == "error")
    level = spdlog::level::err;
  else if (label == "critical")
    level = spdlog::level::critical;
  else if (label == "off")
    level = spdlog::level::off;
  else {
    // We are not pushing back what we couldn't parse.  Seems to be OK.
    in.setstate(std::ios_base::failbit);
  }
  return in;
}

std::ostream& operator<<(std::ostream& out,
                         const spdlog::level::level_enum& level) {
  switch (level) {
    case spdlog::level::trace:
      return out << "trace";
    case spdlog::level::debug:
      return out << "debug";
    case spdlog::level::info:
      return out << "info";
    case spdlog::level::warn:
      return out << "warning";
    case spdlog::level::err:
      return out << "error";
    case spdlog::level::critical:
      return out << "critical";
    case spdlog::level::off:
      return out << "off";
    default:
      throw std::logic_error("unknown logging level");
  }
}
}  // namespace level
}  // namespace spdlog

class GlobalOptions {
 public:
  rang::control color{rang::control::Auto};
  spdlog::level::level_enum log_level{spdlog::level::warn};
};
