#ifndef _WEDPR_UTILITIES_H_
#define _WEDPR_UTILITIES_H_

#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <new>
#include <ostream>

extern "C" {

struct CInputBuffer
{
    const char* data;
    uintptr_t len;
};

struct COutputBuffer
{
    char* data;
    uintptr_t len;
};

const int8_t WEDPR_ERROR = -1;
const int8_t WEDPR_SUCCESS = 0;
}  // extern "C"

#endif
