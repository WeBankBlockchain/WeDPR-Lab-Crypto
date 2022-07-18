
#ifndef _WEDPR_DISCRETE_LOGARITHM_H_
#define _WEDPR_DISCRETE_LOGARITHM_H_
#include "WedprUtilities.h"
extern "C" {
/**
 * C interface for 'wedpr_generate_prove_either_equality_relationship_proof'.
 */
int8_t wedpr_generate_prove_either_equality_relationship_proof(uint64_t c1_value,
                                                               uint64_t c2_value,
                                                               const CInputBuffer *c1_blinding,
                                                               const CInputBuffer *c2_blinding,
                                                               const CInputBuffer *c3_blinding,
                                                               const CInputBuffer *c_basepoint_data,
                                                               const CInputBuffer *blinding_basepoint_data,
                                                               struct CBalanceProof *c_balance_proof);

/**
 * C interface for 'wedpr_verify_either_equality_relationship_proof'.
 */
int8_t wedpr_verify_either_equality_relationship_proof(const CInputBuffer *c1_point_data,
                                                       const CInputBuffer *c2_point_data,
                                                       const CInputBuffer *c3_point_data,
                                                       const struct CBalanceProof *proof,
                                                       const CInputBuffer *c_basepoint_data,
                                                       const CInputBuffer *blinding_basepoint_data);

/**
 * C interface for 'wedpr_generate_prove_knowledge_proof'.
 */
int8_t wedpr_generate_prove_knowledge_proof(uint64_t c_value,
                                            const CInputBuffer *c_blinding_data,
                                            const CInputBuffer *c_basepoint_data,
                                            const CInputBuffer *blinding_basepoint_data,
                                            struct CKnowledgeProof *generated_proof);

/**
 * C interface for 'wedpr_verify_knowledge_proof'.
 */
int8_t wedpr_verify_knowledge_proof(const CInputBuffer *c_point_data,
                                    const struct CKnowledgeProof *proof,
                                    const CInputBuffer *c_basepoint_data,
                                    const CInputBuffer *blinding_basepoint_data);

/**
 * C interface for 'wedpr_generate_prove_format_proof'.
 */
int8_t wedpr_generate_prove_format_proof(uint64_t c1_value,
                                         const CInputBuffer *c_blinding_data,
                                         const CInputBuffer *c1_basepoint_data,
                                         const CInputBuffer *c2_basepoint_data,
                                         const CInputBuffer *blinding_basepoint_data,
                                         struct CFormatProof *generated_format_proof);

/**
 * C interface for 'wedpr_verify_format_proof'.
 */
int8_t wedpr_verify_format_proof(const CInputBuffer *c1_point_data,
                                 const CInputBuffer *c2_point_data,
                                 const struct CFormatProof *proof,
                                 const CInputBuffer *c1_basepoint_data,
                                 const CInputBuffer *c2_basepoint_data,
                                 const CInputBuffer *blinding_basepoint_data);

/**
 * C interface for 'wedpr_generate_prove_sum_relationship'.
 */
int8_t wedpr_generate_prove_sum_relationship(uint64_t c1_value,
                                             uint64_t c2_value,
                                             const CInputBuffer *c1_blinding_data,
                                             const CInputBuffer *c2_blinding_data,
                                             const CInputBuffer *c3_blinding_data,
                                             const CInputBuffer *value_basepoint_data,
                                             const CInputBuffer *blinding_basepoint_data,
                                             struct CArithmeticProof *proof);

/**
 * C interface for 'wedpr_verify_sum_relationship'.
 */
int8_t wedpr_verify_sum_relationship(const CInputBuffer *c1_point_data,
                                     const CInputBuffer *c2_point_data,
                                     const CInputBuffer *c3_point_data,
                                     const struct CArithmeticProof *proof,
                                     const CInputBuffer *value_basepoint_data,
                                     const CInputBuffer *blinding_basepoint_data);

/**
 * C interface for 'wedpr_generate_prove_product_relationship'.
 */
int8_t wedpr_generate_prove_product_relationship(uint64_t c1_value,
                                                 uint64_t c2_value,
                                                 const CInputBuffer *c1_blinding_data,
                                                 const CInputBuffer *c2_blinding_data,
                                                 const CInputBuffer *c3_blinding_data,
                                                 const CInputBuffer *value_basepoint_data,
                                                 const CInputBuffer *blinding_basepoint_data,
                                                 struct CArithmeticProof *generated_proof);

/**
 * C interface for 'wedpr_verify_product_relationship'.
 */
int8_t wedpr_verify_product_relationship(const CInputBuffer *c1_point_data,
                                         const CInputBuffer *c2_point_data,
                                         const CInputBuffer *c3_point_data,
                                         const struct CArithmeticProof *proof,
                                         const CInputBuffer *value_basepoint_data,
                                         const CInputBuffer *blinding_basepoint_data);

/**
 * C interface for 'wedpr_generate_prove_equality_relationship_proof'.
 */
int8_t wedpr_generate_prove_equality_relationship_proof(const CInputBuffer *c1_value_data,
                                                        const CInputBuffer *basepoint1_data,
                                                        const CInputBuffer *basepoint2_data,
                                                        struct CEqualityProof *generated_proof);

/**
 * C interface for 'wedpr_verify_equality_relationship_proof'.
 */
int8_t wedpr_verify_equality_relationship_proof(const CInputBuffer *c1_point_data,
                                                const CInputBuffer *c2_point_data,
                                                const struct CEqualityProof *proof,
                                                const CInputBuffer *basepoint1_data,
                                                const CInputBuffer *basepoint2_data);
}
#endif