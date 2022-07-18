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

typedef struct CBalanceProof {
  char *check1;
  char *check2;
  char *m1;
  char *m2;
  char *m3;
  char *m4;
  char *m5;
  char *m6;
  uintptr_t scalar_len;
} CBalanceProof;

typedef struct CKnowledgeProof {
  char *t1;
  char *m1;
  char *m2;
  uintptr_t scalar_len;
  uintptr_t point_len;
} CKnowledgeProof;

typedef struct CFormatProof {
  char *t1;
  char *t2;
  char *m1;
  char *m2;
  uintptr_t scalar_len;
  uintptr_t point_len;
} CFormatProof;

typedef struct CArithmeticProof {
  char *t1;
  char *t2;
  char *t3;
  char *m1;
  char *m2;
  char *m3;
  char *m4;
  char *m5;
  uintptr_t scalar_len;
  uintptr_t point_len;
} CArithmeticProof;

typedef struct CEqualityProof {
  char *t1;
  char *t2;
  char *m1;
  uintptr_t scalar_len;
  uintptr_t point_len;
} CEqualityProof;

const int8_t WEDPR_ERROR = -1;
const int8_t WEDPR_SUCCESS = 0;
}  // extern "C"

#endif
