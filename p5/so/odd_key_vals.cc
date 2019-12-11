#include "../common/functypes.h"

extern "C" {

/// This mapper returns the value, but only if the integer interpretation of the
/// bytes of the key starting at the second position results in an odd number
vec map(std::string key, vec val) {
  vec res;
  if ((atoi(key.c_str() + 1) & 1))
    return val;
  return res;
}

/// This reducer concatenates all results, twice each, into a newline-delimited
/// list
vec reduce(std::vector<vec> results) {
  vec res;
  for (auto r : results) {
    if (r.size() > 0) {
      if (res.size() != 0)
        vec_append(res, "\n");
      vec_append(res, r);
      vec_append(res, r);
    }
  }
  return res;
}
}