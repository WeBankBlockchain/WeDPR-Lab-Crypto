use wedpr_ffi_common::utils::{
    c_read_raw_data_pointer, c_write_data_to_pointer,
};
use wedpr_l_crypto_zkp_utils::{
    bytes_to_point, bytes_to_scalar, point_to_slice, scalar_to_slice,
    ArithmeticProof, BalanceProof, EqualityProof, FormatProof, KnowledgeProof,
};
use wedpr_l_utils::error::WedprError;

// From Rust to C/C++.
use libc::c_char;

#[repr(C)]
pub struct CBalanceProof {
    pub check1: *mut c_char,
    pub check2: *mut c_char,
    pub m1: *mut c_char,
    pub m2: *mut c_char,
    pub m3: *mut c_char,
    pub m4: *mut c_char,
    pub m5: *mut c_char,
    pub m6: *mut c_char,
    pub scalar_len: usize,
}

#[repr(C)]
pub struct CKnowledgeProof {
    pub t1: *mut c_char,
    pub m1: *mut c_char,
    pub m2: *mut c_char,
    pub scalar_len: usize,
    pub point_len: usize,
}

#[repr(C)]
pub struct CFormatProof {
    pub t1: *mut c_char,
    pub t2: *mut c_char,
    pub m1: *mut c_char,
    pub m2: *mut c_char,
    pub scalar_len: usize,
    pub point_len: usize,
}

#[repr(C)]
pub struct CArithmeticProof {
    pub t1: *mut c_char,
    pub t2: *mut c_char,
    pub t3: *mut c_char,
    pub m1: *mut c_char,
    pub m2: *mut c_char,
    pub m3: *mut c_char,
    pub m4: *mut c_char,
    pub m5: *mut c_char,
    pub scalar_len: usize,
    pub point_len: usize,
}

#[repr(C)]
pub struct CEqualityProof {
    pub t1: *mut c_char,
    pub t2: *mut c_char,
    pub m1: *mut c_char,
    pub scalar_len: usize,
    pub point_len: usize,
}

pub unsafe fn write_balance_proof(
    balance_proof: &BalanceProof,
    c_balance_proof: &mut CBalanceProof,
) {
    // check1
    c_write_data_to_pointer(
        &scalar_to_slice(&balance_proof.check1),
        c_balance_proof.check1,
        c_balance_proof.scalar_len,
    );
    // check2
    c_write_data_to_pointer(
        &scalar_to_slice(&balance_proof.check2),
        c_balance_proof.check2,
        c_balance_proof.scalar_len,
    );
    // m1
    c_write_data_to_pointer(
        &scalar_to_slice(&balance_proof.m1),
        c_balance_proof.m1,
        c_balance_proof.scalar_len,
    );
    // m2
    c_write_data_to_pointer(
        &scalar_to_slice(&balance_proof.m2),
        c_balance_proof.m2,
        c_balance_proof.scalar_len,
    );
    // m3
    c_write_data_to_pointer(
        &scalar_to_slice(&balance_proof.m3),
        c_balance_proof.m3,
        c_balance_proof.scalar_len,
    );
    // m4
    c_write_data_to_pointer(
        &scalar_to_slice(&balance_proof.m4),
        c_balance_proof.m4,
        c_balance_proof.scalar_len,
    );
    // m5
    c_write_data_to_pointer(
        &scalar_to_slice(&balance_proof.m5),
        c_balance_proof.m5,
        c_balance_proof.scalar_len,
    );
    // m6
    c_write_data_to_pointer(
        &scalar_to_slice(&balance_proof.m6),
        c_balance_proof.m6,
        c_balance_proof.scalar_len,
    );
}

pub unsafe fn read_c_balance_proof(
    c_balance_proof: &CBalanceProof,
) -> Result<BalanceProof, WedprError> {
    let check1 = bytes_to_scalar(
        c_read_raw_data_pointer(
            c_balance_proof.check1,
            c_balance_proof.scalar_len,
        )
        .as_slice(),
    )?;
    let check2 = bytes_to_scalar(
        c_read_raw_data_pointer(
            c_balance_proof.check2,
            c_balance_proof.scalar_len,
        )
        .as_slice(),
    )?;
    let m1 = bytes_to_scalar(
        c_read_raw_data_pointer(c_balance_proof.m1, c_balance_proof.scalar_len)
            .as_slice(),
    )?;
    let m2 = bytes_to_scalar(
        c_read_raw_data_pointer(c_balance_proof.m2, c_balance_proof.scalar_len)
            .as_slice(),
    )?;
    let m3 = bytes_to_scalar(
        c_read_raw_data_pointer(c_balance_proof.m3, c_balance_proof.scalar_len)
            .as_slice(),
    )?;
    let m4 = bytes_to_scalar(
        c_read_raw_data_pointer(c_balance_proof.m4, c_balance_proof.scalar_len)
            .as_slice(),
    )?;
    let m5 = bytes_to_scalar(
        c_read_raw_data_pointer(c_balance_proof.m5, c_balance_proof.scalar_len)
            .as_slice(),
    )?;
    let m6 = bytes_to_scalar(
        c_read_raw_data_pointer(c_balance_proof.m6, c_balance_proof.scalar_len)
            .as_slice(),
    )?;
    return Ok(BalanceProof {
        check1: check1,
        check2: check2,
        m1: m1,
        m2: m2,
        m3: m3,
        m4: m4,
        m5: m5,
        m6: m6,
    });
}

pub unsafe fn write_knowledger_proof(
    knowledge_proof: &KnowledgeProof,
    c_knowledge_proof: &mut CKnowledgeProof,
) {
    c_write_data_to_pointer(
        &point_to_slice(&knowledge_proof.t1),
        c_knowledge_proof.t1,
        c_knowledge_proof.point_len,
    );
    c_write_data_to_pointer(
        &scalar_to_slice(&knowledge_proof.m1),
        c_knowledge_proof.m1,
        c_knowledge_proof.scalar_len,
    );
    c_write_data_to_pointer(
        &scalar_to_slice(&knowledge_proof.m2),
        c_knowledge_proof.m2,
        c_knowledge_proof.scalar_len,
    );
}

pub unsafe fn read_c_knowledge_proof(
    c_knowledge_proof: &CKnowledgeProof,
) -> Result<KnowledgeProof, WedprError> {
    let t1 = bytes_to_point(
        c_read_raw_data_pointer(
            c_knowledge_proof.t1,
            c_knowledge_proof.point_len,
        )
        .as_slice(),
    )?;
    let m1 = bytes_to_scalar(
        c_read_raw_data_pointer(
            c_knowledge_proof.m1,
            c_knowledge_proof.scalar_len,
        )
        .as_slice(),
    )?;
    let m2 = bytes_to_scalar(
        c_read_raw_data_pointer(
            c_knowledge_proof.m2,
            c_knowledge_proof.scalar_len,
        )
        .as_slice(),
    )?;
    return Ok(KnowledgeProof {
        t1: t1,
        m1: m1,
        m2: m2,
    });
}

pub unsafe fn write_format_proof(
    format_proof: &FormatProof,
    c_format_proof: &mut CFormatProof,
) {
    c_write_data_to_pointer(
        &point_to_slice(&format_proof.t1),
        c_format_proof.t1,
        c_format_proof.point_len,
    );
    c_write_data_to_pointer(
        &point_to_slice(&format_proof.t2),
        c_format_proof.t2,
        c_format_proof.point_len,
    );
    c_write_data_to_pointer(
        &scalar_to_slice(&format_proof.m1),
        c_format_proof.m1,
        c_format_proof.scalar_len,
    );
    c_write_data_to_pointer(
        &scalar_to_slice(&format_proof.m2),
        c_format_proof.m2,
        c_format_proof.scalar_len,
    );
}

pub unsafe fn read_c_format_proof(
    c_format_proof: &CFormatProof,
) -> Result<FormatProof, WedprError> {
    let t1 = bytes_to_point(
        c_read_raw_data_pointer(c_format_proof.t1, c_format_proof.point_len)
            .as_slice(),
    )?;
    let t2 = bytes_to_point(
        c_read_raw_data_pointer(c_format_proof.t2, c_format_proof.point_len)
            .as_slice(),
    )?;
    let m1 = bytes_to_scalar(
        c_read_raw_data_pointer(c_format_proof.m1, c_format_proof.scalar_len)
            .as_slice(),
    )?;
    let m2 = bytes_to_scalar(
        c_read_raw_data_pointer(c_format_proof.m2, c_format_proof.scalar_len)
            .as_slice(),
    )?;
    return Ok(FormatProof {
        t1: t1,
        t2: t2,
        m1: m1,
        m2: m2,
    });
}

pub unsafe fn write_arithmetic_proof(
    arithmetic_proof: &ArithmeticProof,
    c_arithmetic_proof_proof: &mut CArithmeticProof,
) {
    c_write_data_to_pointer(
        &point_to_slice(&arithmetic_proof.t1),
        c_arithmetic_proof_proof.t1,
        c_arithmetic_proof_proof.point_len,
    );
    c_write_data_to_pointer(
        &point_to_slice(&arithmetic_proof.t2),
        c_arithmetic_proof_proof.t2,
        c_arithmetic_proof_proof.point_len,
    );
    c_write_data_to_pointer(
        &point_to_slice(&arithmetic_proof.t3),
        c_arithmetic_proof_proof.t3,
        c_arithmetic_proof_proof.point_len,
    );
    c_write_data_to_pointer(
        &scalar_to_slice(&arithmetic_proof.m1),
        c_arithmetic_proof_proof.m1,
        c_arithmetic_proof_proof.scalar_len,
    );
    c_write_data_to_pointer(
        &scalar_to_slice(&arithmetic_proof.m2),
        c_arithmetic_proof_proof.m2,
        c_arithmetic_proof_proof.scalar_len,
    );
    c_write_data_to_pointer(
        &scalar_to_slice(&arithmetic_proof.m3),
        c_arithmetic_proof_proof.m3,
        c_arithmetic_proof_proof.scalar_len,
    );
    c_write_data_to_pointer(
        &scalar_to_slice(&arithmetic_proof.m4),
        c_arithmetic_proof_proof.m4,
        c_arithmetic_proof_proof.scalar_len,
    );
    c_write_data_to_pointer(
        &scalar_to_slice(&arithmetic_proof.m5),
        c_arithmetic_proof_proof.m5,
        c_arithmetic_proof_proof.scalar_len,
    );
}

pub unsafe fn read_c_arithmetic_proof(
    c_arithmetic_proof: &CArithmeticProof,
) -> Result<ArithmeticProof, WedprError> {
    let t1 = bytes_to_point(
        c_read_raw_data_pointer(
            c_arithmetic_proof.t1,
            c_arithmetic_proof.point_len,
        )
        .as_slice(),
    )?;
    let t2 = bytes_to_point(
        c_read_raw_data_pointer(
            c_arithmetic_proof.t2,
            c_arithmetic_proof.point_len,
        )
        .as_slice(),
    )?;
    let t3 = bytes_to_point(
        c_read_raw_data_pointer(
            c_arithmetic_proof.t3,
            c_arithmetic_proof.point_len,
        )
        .as_slice(),
    )?;
    let m1 = bytes_to_scalar(
        c_read_raw_data_pointer(
            c_arithmetic_proof.m1,
            c_arithmetic_proof.scalar_len,
        )
        .as_slice(),
    )?;
    let m2 = bytes_to_scalar(
        c_read_raw_data_pointer(
            c_arithmetic_proof.m2,
            c_arithmetic_proof.scalar_len,
        )
        .as_slice(),
    )?;
    let m3 = bytes_to_scalar(
        c_read_raw_data_pointer(
            c_arithmetic_proof.m3,
            c_arithmetic_proof.scalar_len,
        )
        .as_slice(),
    )?;
    let m4 = bytes_to_scalar(
        c_read_raw_data_pointer(
            c_arithmetic_proof.m4,
            c_arithmetic_proof.scalar_len,
        )
        .as_slice(),
    )?;
    let m5 = bytes_to_scalar(
        c_read_raw_data_pointer(
            c_arithmetic_proof.m5,
            c_arithmetic_proof.scalar_len,
        )
        .as_slice(),
    )?;
    return Ok(ArithmeticProof {
        t1: t1,
        t2: t2,
        t3: t3,
        m1: m1,
        m2: m2,
        m3: m3,
        m4: m4,
        m5: m5,
    });
}

pub unsafe fn write_equality_proof(
    equality_proof: &EqualityProof,
    c_equality_proof: &mut CEqualityProof,
) {
    c_write_data_to_pointer(
        &scalar_to_slice(&equality_proof.m1),
        c_equality_proof.m1,
        c_equality_proof.scalar_len,
    );
    c_write_data_to_pointer(
        &point_to_slice(&equality_proof.t1),
        c_equality_proof.t1,
        c_equality_proof.point_len,
    );
    c_write_data_to_pointer(
        &point_to_slice(&equality_proof.t2),
        c_equality_proof.t2,
        c_equality_proof.point_len,
    );
}

pub unsafe fn read_c_equality_proof(
    c_equality_proof: &CEqualityProof,
) -> Result<EqualityProof, WedprError> {
    let m1 = bytes_to_scalar(
        c_read_raw_data_pointer(
            c_equality_proof.m1,
            c_equality_proof.scalar_len,
        )
        .as_slice(),
    )?;
    let t1 = bytes_to_point(
        c_read_raw_data_pointer(
            c_equality_proof.t1,
            c_equality_proof.point_len,
        )
        .as_slice(),
    )?;
    let t2 = bytes_to_point(
        c_read_raw_data_pointer(
            c_equality_proof.t2,
            c_equality_proof.point_len,
        )
        .as_slice(),
    )?;
    return Ok(EqualityProof {
        m1: m1,
        t1: t1,
        t2: t2,
    });
}
