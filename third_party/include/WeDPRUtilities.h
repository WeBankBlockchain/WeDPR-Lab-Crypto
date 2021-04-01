#ifndef _WEDPR_UTILITIES_H_
#define _WEDPR_UTILITIES_H_

#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <new>
#include <ostream>
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
#endif
