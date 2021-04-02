#ifndef _WEDPR_BN128_H_
#define _WEDPR_BN128_H_
#include "WeDPRUtilities.h"

extern "C" {

/// C interface for 'wedpr_fb_alt_bn128_g1_add'.
int8_t wedpr_fb_alt_bn128_g1_add(const CInputBuffer* raw_pairing_data, COutputBuffer* output_point);

/// C interface for 'wedpr_fb_alt_bn128_g1_mul'.
int8_t wedpr_fb_alt_bn128_g1_mul(const CInputBuffer* raw_pairing_data, COutputBuffer* output_point);

/// C interface for 'wedpr_fb_alt_bn128_pairing_product'.
int8_t wedpr_fb_alt_bn128_pairing_product(
    const CInputBuffer* raw_pairing_data, COutputBuffer* output_point);

}  // extern "C"
#endif
