use crate::utils::{
    c_input_buffer_to_point, c_input_buffer_to_scalar, read_c_arithmetic_proof,
    read_c_balance_proof, read_c_equality_proof, read_c_format_proof,
    read_c_knowledge_proof, write_arithmetic_proof, write_balance_proof,
    write_equality_proof, write_format_proof, write_knowledger_proof,
};
use wedpr_ffi_common::utils::{CInputBuffer, COutputBuffer, FAILURE, SUCCESS};
use wedpr_l_crypto_zkp_utils::point_to_slice;

use wedpr_ffi_common::utils::c_write_data_to_pointer;

#[cfg(feature = "wedpr_f_zkp_proof")]
use wedpr_l_crypto_zkp_discrete_logarithm_proof::{
    aggregate_ristretto_point, prove_either_equality_relationship_proof,
    prove_equality_relationship_proof, prove_format_proof,
    prove_knowledge_proof, prove_product_relationship, prove_sum_relationship,
    verify_either_equality_relationship_proof,
    verify_equality_relationship_proof, verify_format_proof,
    verify_knowledge_proof, verify_product_relationship,
    verify_sum_relationship,
};

#[no_mangle]
/// C interface for 'wedpr_aggregate_ristretto_point'.
pub unsafe extern "C" fn wedpr_aggregate_ristretto_point(
    point_sum_data: &CInputBuffer,
    point_share_data: &CInputBuffer,
    result_data: &mut COutputBuffer,
) -> i8 {
    // point_sum
    let point_sum_result = c_input_buffer_to_point(&point_sum_data);
    let point_sum = match point_sum_result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };

    // point_share
    let point_share_result = c_input_buffer_to_point(&point_share_data);
    let point_share = match point_share_result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    let sum_result = aggregate_ristretto_point(&point_sum, &point_share);
    let sum = match sum_result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    // write the point_sum
    c_write_data_to_pointer(
        &point_to_slice(&sum),
        result_data.data,
        result_data.len,
    );
    SUCCESS
}

#[no_mangle]
/// C interface for 'wedpr_generate_prove_either_equality_relationship_proof'.
pub unsafe extern "C" fn wedpr_generate_prove_either_equality_relationship_proof(
    c1_value: u64,
    c2_value: u64,
    c1_blinding: &CInputBuffer,
    c2_blinding: &CInputBuffer,
    c3_blinding: &CInputBuffer,
    c_basepoint_data: &CInputBuffer,
    blinding_basepoint_data: &CInputBuffer,
    c_balance_proof: &mut COutputBuffer,
) -> i8 {
    // c1_blinding
    let c1_blinding_result = c_input_buffer_to_scalar(&c1_blinding);
    let c1_blinding_value = match c1_blinding_result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    // c2_blinding
    let c2_blinding_result = c_input_buffer_to_scalar(&c2_blinding);
    let c2_blinding_value = match c2_blinding_result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };

    // c3_blinding
    let c3_blinding_result = c_input_buffer_to_scalar(c3_blinding);
    let c3_blinding_value = match c3_blinding_result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    // c_basepoint
    let c_basepoint_result = c_input_buffer_to_point(c_basepoint_data);
    let c_basepoint = match c_basepoint_result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    // blinding_basepoint
    let blinding_basepoint_result =
        c_input_buffer_to_point(blinding_basepoint_data);
    let blinding_basepoint = match blinding_basepoint_result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    let proof = prove_either_equality_relationship_proof(
        c1_value,
        c2_value,
        &c1_blinding_value,
        &c2_blinding_value,
        &c3_blinding_value,
        &c_basepoint,
        &blinding_basepoint,
    );
    // write balance proof back to c_balance_proof
    write_balance_proof(&proof, c_balance_proof);
    SUCCESS
}

#[no_mangle]
/// C interface for 'wedpr_verify_either_equality_relationship_proof'.
pub unsafe extern "C" fn wedpr_verify_either_equality_relationship_proof(
    c1_point_data: &CInputBuffer,
    c2_point_data: &CInputBuffer,
    c3_point_data: &CInputBuffer,
    proof: &CInputBuffer,
    c_basepoint_data: &CInputBuffer,
    blinding_basepoint_data: &CInputBuffer,
) -> i8 {
    // c1_point
    let c1_point_result = c_input_buffer_to_point(c1_point_data);
    let c1_point = match c1_point_result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    // c2_point
    let c2_point_result = c_input_buffer_to_point(c2_point_data);
    let c2_point = match c2_point_result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    // c3_point
    let c3_point_result = c_input_buffer_to_point(c3_point_data);
    let c3_point = match c3_point_result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    // balance_proof
    let balance_proof_result = read_c_balance_proof(proof);
    let balance_proof = match balance_proof_result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    // c_basepoint
    let c_basepoint_result = c_input_buffer_to_point(c_basepoint_data);
    let c_basepoint = match c_basepoint_result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    // blinding_basepoint
    let blinding_basepoint_result =
        c_input_buffer_to_point(blinding_basepoint_data);
    let blinding_basepoint = match blinding_basepoint_result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    let result = verify_either_equality_relationship_proof(
        &c1_point,
        &c2_point,
        &c3_point,
        &balance_proof,
        &c_basepoint,
        &blinding_basepoint,
    );
    let verify_result = match result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    if verify_result {
        return SUCCESS;
    }
    FAILURE
}

#[no_mangle]
/// C interface for 'wedpr_generate_prove_knowledge_proof'.
pub unsafe extern "C" fn wedpr_generate_prove_knowledge_proof(
    c_value: u64,
    c_blinding_data: &CInputBuffer,
    c_basepoint_data: &CInputBuffer,
    blinding_basepoint_data: &CInputBuffer,
    generated_proof: &mut COutputBuffer,
) -> i8 {
    // c_blinding
    let c_blinding_result = c_input_buffer_to_scalar(c_blinding_data);
    let c_blinding_value = match c_blinding_result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };

    // c_basepoint
    let c_basepoint_result = c_input_buffer_to_point(c_basepoint_data);
    let c_basepoint = match c_basepoint_result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    // blinding_basepoint
    let blinding_basepoint_result =
        c_input_buffer_to_point(blinding_basepoint_data);
    let blinding_basepoint = match blinding_basepoint_result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    let proof = prove_knowledge_proof(
        c_value,
        &c_blinding_value,
        &c_basepoint,
        &blinding_basepoint,
    );
    // write the KnowledgeProof
    write_knowledger_proof(&proof, generated_proof);
    SUCCESS
}

#[no_mangle]
/// C interface for 'wedpr_verify_knowledge_proof'.
pub unsafe extern "C" fn wedpr_verify_knowledge_proof(
    c_point_data: &CInputBuffer,
    proof: &CInputBuffer,
    c_basepoint_data: &CInputBuffer,
    blinding_basepoint_data: &CInputBuffer,
) -> i8 {
    // c_point
    let c_point_result = c_input_buffer_to_point(c_point_data);
    let c_point = match c_point_result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    // KnowledgeProof
    let knowledge_proof_result = read_c_knowledge_proof(proof);
    let knowledge_proof = match knowledge_proof_result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    // c_basepoint
    let c_basepoint_result = c_input_buffer_to_point(c_basepoint_data);
    let c_basepoint = match c_basepoint_result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    // blinding_basepoint
    let blinding_basepoint_result =
        c_input_buffer_to_point(blinding_basepoint_data);
    let blinding_basepoint = match blinding_basepoint_result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    // verify_knowledge_proof
    let result = verify_knowledge_proof(
        &c_point,
        &knowledge_proof,
        &c_basepoint,
        &blinding_basepoint,
    );
    let verify_result = match result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    if verify_result {
        return SUCCESS;
    }
    FAILURE
}

#[no_mangle]
/// C interface for 'wedpr_generate_prove_format_proof'.
pub unsafe extern "C" fn wedpr_generate_prove_format_proof(
    c1_value: u64,
    c_blinding_data: &CInputBuffer,
    c1_basepoint_data: &CInputBuffer,
    c2_basepoint_data: &CInputBuffer,
    blinding_basepoint_data: &CInputBuffer,
    generated_format_proof: &mut COutputBuffer,
) -> i8 {
    // c_blinding
    let c_blinding_data_result = c_input_buffer_to_scalar(c_blinding_data);
    let c_blinding_value = match c_blinding_data_result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    // c1_basepoint
    let c1_basepoint_result = c_input_buffer_to_point(c1_basepoint_data);
    let c1_basepoint = match c1_basepoint_result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    // c2_basepoint
    let c2_basepoint_result = c_input_buffer_to_point(c2_basepoint_data);
    let c2_basepoint = match c2_basepoint_result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    // blinding_basepoint
    let blinding_basepoint_result =
        c_input_buffer_to_point(blinding_basepoint_data);
    let blinding_basepoint = match blinding_basepoint_result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    let proof = prove_format_proof(
        c1_value,
        &c_blinding_value,
        &c1_basepoint,
        &c2_basepoint,
        &blinding_basepoint,
    );
    write_format_proof(&proof, generated_format_proof);
    SUCCESS
}

#[no_mangle]
/// C interface for 'wedpr_verify_format_proof'.
pub unsafe extern "C" fn wedpr_verify_format_proof(
    c1_point_data: &CInputBuffer,
    c2_point_data: &CInputBuffer,
    proof: &CInputBuffer,
    c1_basepoint_data: &CInputBuffer,
    c2_basepoint_data: &CInputBuffer,
    blinding_basepoint_data: &CInputBuffer,
) -> i8 {
    // c1_point
    let c1_point_result = c_input_buffer_to_point(c1_point_data);
    let c1_point = match c1_point_result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    // c2_point
    let c2_point_result = c_input_buffer_to_point(c2_point_data);
    let c2_point = match c2_point_result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    // format_proof
    let format_proof_result = read_c_format_proof(proof);
    let format_proof = match format_proof_result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    // c1_basepoint
    let c1_basepoint_result = c_input_buffer_to_point(c1_basepoint_data);
    let c1_basepoint = match c1_basepoint_result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    // c2_basepoint
    let c2_basepoint_result = c_input_buffer_to_point(c2_basepoint_data);
    let c2_basepoint = match c2_basepoint_result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    // blinding_basepoint
    let blinding_basepoint_result =
        c_input_buffer_to_point(blinding_basepoint_data);
    let blinding_basepoint = match blinding_basepoint_result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };

    // verify_format_proof
    let result = verify_format_proof(
        &c1_point,
        &c2_point,
        &format_proof,
        &c1_basepoint,
        &c2_basepoint,
        &blinding_basepoint,
    );
    let verify_result = match result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    if verify_result {
        return SUCCESS;
    }
    return FAILURE;
}

#[no_mangle]
/// C interface for 'wedpr_generate_prove_sum_relationship'.
pub unsafe extern "C" fn wedpr_generate_prove_sum_relationship(
    c1_value: u64,
    c2_value: u64,
    c1_blinding_data: &CInputBuffer,
    c2_blinding_data: &CInputBuffer,
    c3_blinding_data: &CInputBuffer,
    value_basepoint_data: &CInputBuffer,
    blinding_basepoint_data: &CInputBuffer,
    proof: &mut COutputBuffer,
) -> i8 {
    // c1_blinding
    let c1_blinding_result = c_input_buffer_to_scalar(c1_blinding_data);
    let c1_blinding = match c1_blinding_result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    // c2_blinding
    let c2_blinding_result = c_input_buffer_to_scalar(c2_blinding_data);
    let c2_blinding = match c2_blinding_result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    // c3_blinding
    let c3_blinding_result = c_input_buffer_to_scalar(c3_blinding_data);
    let c3_blinding = match c3_blinding_result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    // value_basepoint
    let value_basepoint_result = c_input_buffer_to_point(value_basepoint_data);
    let value_basepoint = match value_basepoint_result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    // blinding_basepoint
    let blinding_basepoint_result =
        c_input_buffer_to_point(blinding_basepoint_data);
    let blinding_basepoint = match blinding_basepoint_result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    let arithmetic_proof = prove_sum_relationship(
        c1_value,
        c2_value,
        &c1_blinding,
        &c2_blinding,
        &c3_blinding,
        &value_basepoint,
        &blinding_basepoint,
    );
    write_arithmetic_proof(&arithmetic_proof, proof);
    SUCCESS
}

#[no_mangle]
/// C interface for 'wedpr_verify_sum_relationship'.
pub unsafe extern "C" fn wedpr_verify_sum_relationship(
    c1_point_data: &CInputBuffer,
    c2_point_data: &CInputBuffer,
    c3_point_data: &CInputBuffer,
    proof: &CInputBuffer,
    value_basepoint_data: &CInputBuffer,
    blinding_basepoint_data: &CInputBuffer,
) -> i8 {
    // c1_point
    let c1_point_result = c_input_buffer_to_point(c1_point_data);
    let c1_point = match c1_point_result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    // c2_point
    let c2_point_result = c_input_buffer_to_point(c2_point_data);
    let c2_point = match c2_point_result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    // c3_point
    let c3_point_result = c_input_buffer_to_point(c3_point_data);
    let c3_point = match c3_point_result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    // proof
    let arithmetic_proof_result = read_c_arithmetic_proof(proof);
    let arithmetic_proof = match arithmetic_proof_result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    // value_basepoint
    let value_basepoint_result = c_input_buffer_to_point(value_basepoint_data);
    let value_basepoint = match value_basepoint_result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    // blinding_basepoint
    let blinding_basepoint_result =
        c_input_buffer_to_point(blinding_basepoint_data);
    let blinding_basepoint = match blinding_basepoint_result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    let result = verify_sum_relationship(
        &c1_point,
        &c2_point,
        &c3_point,
        &arithmetic_proof,
        &value_basepoint,
        &blinding_basepoint,
    );
    let verify_result = match result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    if verify_result {
        return SUCCESS;
    }
    return FAILURE;
}

#[no_mangle]
/// C interface for 'wedpr_generate_prove_product_relationship'.
pub unsafe extern "C" fn wedpr_generate_prove_product_relationship(
    c1_value: u64,
    c2_value: u64,
    c1_blinding_data: &CInputBuffer,
    c2_blinding_data: &CInputBuffer,
    c3_blinding_data: &CInputBuffer,
    value_basepoint_data: &CInputBuffer,
    blinding_basepoint_data: &CInputBuffer,
    generated_proof: &mut COutputBuffer,
) -> i8 {
    // c1_blinding
    let c1_blinding_result = c_input_buffer_to_scalar(c1_blinding_data);
    let c1_blinding = match c1_blinding_result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    // c2_blinding
    let c2_blinding_result = c_input_buffer_to_scalar(c2_blinding_data);
    let c2_blinding = match c2_blinding_result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    // c3_blinding
    let c3_blinding_result = c_input_buffer_to_scalar(c3_blinding_data);
    let c3_blinding = match c3_blinding_result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };

    // value_basepoint
    let value_basepoint_result = c_input_buffer_to_point(value_basepoint_data);
    let value_basepoint = match value_basepoint_result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    // blinding_basepoint
    let blinding_basepoint_result =
        c_input_buffer_to_point(blinding_basepoint_data);
    let blinding_basepoint = match blinding_basepoint_result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };

    let proof = prove_product_relationship(
        c1_value,
        c2_value,
        &c1_blinding,
        &c2_blinding,
        &c3_blinding,
        &value_basepoint,
        &blinding_basepoint,
    );
    write_arithmetic_proof(&proof, generated_proof);
    SUCCESS
}

#[no_mangle]
/// C interface for 'wedpr_verify_product_relationship'.
pub unsafe extern "C" fn wedpr_verify_product_relationship(
    c1_point_data: &CInputBuffer,
    c2_point_data: &CInputBuffer,
    c3_point_data: &CInputBuffer,
    proof: &CInputBuffer,
    value_basepoint_data: &CInputBuffer,
    blinding_basepoint_data: &CInputBuffer,
) -> i8 {
    // c1_point
    let c1_point_result = c_input_buffer_to_point(c1_point_data);
    let c1_point = match c1_point_result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    // c2_point
    let c2_point_result = c_input_buffer_to_point(c2_point_data);
    let c2_point = match c2_point_result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    // c3_point
    let c3_point_result = c_input_buffer_to_point(c3_point_data);
    let c3_point = match c3_point_result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    // proof
    let arithmetic_proof_result = read_c_arithmetic_proof(proof);
    let arithmetic_proof = match arithmetic_proof_result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    // value_basepoint
    let value_basepoint_result = c_input_buffer_to_point(value_basepoint_data);
    let value_basepoint = match value_basepoint_result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    // blinding_basepoint
    let blinding_basepoint_result =
        c_input_buffer_to_point(blinding_basepoint_data);
    let blinding_basepoint = match blinding_basepoint_result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    let result = verify_product_relationship(
        &c1_point,
        &c2_point,
        &c3_point,
        &arithmetic_proof,
        &value_basepoint,
        &blinding_basepoint,
    );
    let verify_result = match result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    if verify_result {
        return SUCCESS;
    }
    return FAILURE;
}

#[no_mangle]
/// C interface for 'wedpr_generate_prove_equality_relationship_proof'.
pub unsafe extern "C" fn wedpr_generate_prove_equality_relationship_proof(
    c1_value_data: &CInputBuffer,
    basepoint1_data: &CInputBuffer,
    basepoint2_data: &CInputBuffer,
    generated_proof: &mut COutputBuffer,
) -> i8 {
    // c1_value
    let c1_value_result = c_input_buffer_to_scalar(c1_value_data);
    let c1_value = match c1_value_result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    // basepoint1
    let basepoint1_result = c_input_buffer_to_point(basepoint1_data);
    let basepoint1 = match basepoint1_result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    // basepoint2
    let basepoint2_result = c_input_buffer_to_point(basepoint2_data);
    let basepoint2 = match basepoint2_result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    let equality_proof =
        prove_equality_relationship_proof(&c1_value, &basepoint1, &basepoint2);
    write_equality_proof(&equality_proof, generated_proof);
    SUCCESS
}

#[no_mangle]
/// C interface for 'wedpr_verify_equality_relationship_proof'.
pub unsafe extern "C" fn wedpr_verify_equality_relationship_proof(
    c1_point_data: &CInputBuffer,
    c2_point_data: &CInputBuffer,
    proof: &CInputBuffer,
    basepoint1_data: &CInputBuffer,
    basepoint2_data: &CInputBuffer,
) -> i8 {
    // c1_point
    let c1_point_result = c_input_buffer_to_point(c1_point_data);
    let c1_point = match c1_point_result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    // c2_point
    let c2_point_result = c_input_buffer_to_point(c2_point_data);
    let c2_point = match c2_point_result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    // proof
    let equality_proof_result = read_c_equality_proof(proof);
    let equality_proof = match equality_proof_result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    // basepoint1
    let basepoint1_result = c_input_buffer_to_point(basepoint1_data);
    let basepoint1 = match basepoint1_result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    // basepoint2
    let basepoint2_result = c_input_buffer_to_point(basepoint2_data);
    let basepoint2 = match basepoint2_result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    // verify_equality_relationship_proof
    let result = verify_equality_relationship_proof(
        &c1_point,
        &c2_point,
        &equality_proof,
        &basepoint1,
        &basepoint2,
    );
    let verify_result = match result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    if verify_result {
        return SUCCESS;
    }
    return FAILURE;
}
