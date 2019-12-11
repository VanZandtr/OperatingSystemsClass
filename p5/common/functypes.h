#pragma once

#include <string>
#include <vector>

#include "vec.h"

/// A pointer to a function that takes a string and vec and returns a vec
typedef vec (*map_func)(std::string, vec);

/// A pointer to a function that takes a vector<vec> and returns a vec
typedef vec (*reduce_func)(std::vector<vec>);