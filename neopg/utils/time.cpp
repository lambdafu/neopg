#include <boost/date_time/posix_time/conversion.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>

#include <neopg/utils/time.h>

namespace NeoPG {

time_t timegm(struct tm *tm) {
  using namespace boost::posix_time;

  /* FIXME: Not sure if this does the right thing.  */
  ptime pt = ptime_from_tm(*tm);
  return to_time_t(pt);
}

}  // namespace NeoPG
