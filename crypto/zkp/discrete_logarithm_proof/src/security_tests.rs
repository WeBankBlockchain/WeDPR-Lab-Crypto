use super::*;
use wedpr_l_crypto_zkp_utils::{BASEPOINT_G1, BASEPOINT_G2};

fn rejected(result: Result<bool, WedprError>) {
    assert!(!matches!(result, Ok(true)));
}

#[test]
fn zero_coefficient_is_resampled_and_coefficients_use_the_full_field() {
    let mut samples = vec![Scalar::one(), Scalar::zero()].into_iter().rev();
    assert_eq!(
        nonzero_batch_coefficient(|| samples.next().unwrap()),
        Scalar::one()
    );
    for _ in 0..16 {
        let coefficient = nonzero_batch_coefficient(get_random_scalar);
        assert_ne!(coefficient, Scalar::zero());
        assert!(coefficient.to_bytes()[1..].iter().any(|byte| *byte != 0));
    }
}

#[test]
fn every_batch_verifier_rejects_a_single_invalid_proof() {
    let g = *BASEPOINT_G1;
    let h = *BASEPOINT_G2;
    let knowledge = KnowledgeProof::default();
    let format = FormatProof::default();
    let arithmetic = ArithmeticProof::default();
    let equality = EqualityProof::default();
    rejected(verify_knowledge_proof(&g, &knowledge, &g, &h));
    rejected(verify_format_proof(&g, &h, &format, &g, &g, &h));
    rejected(verify_sum_relationship(&g, &h, &g, &arithmetic, &g, &h));
    rejected(verify_product_relationship(&g, &h, &g, &arithmetic, &g, &h));
    rejected(verify_equality_relationship_proof(
        &g, &h, &equality, &g, &h,
    ));
    // With one nonzero error term and a nonzero coefficient rejection is
    // algebraically guaranteed; the old zero coefficient dropped this term.
    for _ in 0..32 {
        rejected(verify_knowledge_proof_in_batch(
            &vec![g],
            &vec![knowledge.clone()],
            &g,
            &h,
        ));
        rejected(verify_format_proof_in_batch(
            &vec![g],
            &vec![h],
            &vec![format.clone()],
            &g,
            &g,
            &h,
        ));
        rejected(verify_sum_relationship_in_batch(
            &vec![g],
            &vec![h],
            &vec![g],
            &vec![arithmetic.clone()],
            &g,
            &h,
        ));
        rejected(verify_product_relationship_in_batch(
            &vec![g],
            &vec![h],
            &vec![g],
            &vec![arithmetic.clone()],
            &g,
            &h,
        ));
        rejected(verify_equality_relationship_proof_in_batch(
            &vec![g],
            &vec![h],
            &vec![equality.clone()],
            &g,
            &h,
        ));
    }
}

#[test]
fn mismatched_lengths_and_empty_batches_are_rejected_without_panics() {
    let g = *BASEPOINT_G1;
    let h = *BASEPOINT_G2;
    for a in 0..=2 {
        for b in 0..=2 {
            if a != b || a == 0 {
                rejected(verify_knowledge_proof_in_batch(
                    &vec![g; a],
                    &vec![KnowledgeProof::default(); b],
                    &g,
                    &h,
                ));
            }
            for p in 0..=2 {
                if a != b || a != p || a == 0 {
                    rejected(verify_format_proof_in_batch(
                        &vec![g; a],
                        &vec![h; b],
                        &vec![FormatProof::default(); p],
                        &g,
                        &g,
                        &h,
                    ));
                    rejected(verify_equality_relationship_proof_in_batch(
                        &vec![g; a],
                        &vec![h; b],
                        &vec![EqualityProof::default(); p],
                        &g,
                        &h,
                    ));
                }
                for c in 0..=2 {
                    if a != b || a != c || a != p || a == 0 {
                        rejected(verify_sum_relationship_in_batch(
                            &vec![g; a],
                            &vec![h; b],
                            &vec![g; c],
                            &vec![ArithmeticProof::default(); p],
                            &g,
                            &h,
                        ));
                        rejected(verify_product_relationship_in_batch(
                            &vec![g; a],
                            &vec![h; b],
                            &vec![g; c],
                            &vec![ArithmeticProof::default(); p],
                            &g,
                            &h,
                        ));
                    }
                }
            }
        }
    }
}
