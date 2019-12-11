#include "../common/functypes.h"
#include <iostream>

extern "C" {

/// This mapper returns the key, without doing any work
vec map(std::string key, vec val) { return vec_from_string(key); }

/// This reducer concatenates all strings into a newline-delimited list
vec reduce(std::vector<vec> results) {
  vec res;
  for (auto r : results) {
    if (res.size() != 0) {
      vec_append(res, "\n");
    }
    vec_append(res, r);
  }
  return res;
}
}