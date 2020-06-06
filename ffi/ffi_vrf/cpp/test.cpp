#include <stdio.h>
#include "ffi_vrf.h"
#include <stdlib.h>

int main()
{
    char* sk = "e82a0751b7671d20d24631faa7033ee6909ed73629e1795e830b8fb8666e17b8";
    char* message = "847adcf9b24cf0041ddff02ffe324e30b1271c5170086f8ee799dd1123dacb2e";
    char* pk = curve25519_vrf_generate_key_pair(sk);
    printf("pk = %s\n", pk);
    int result =  curve25519_vrf_is_valid_pubkey(pk);
    printf("result = %d\n", result);
    char* proof = curve25519_vrf_proof(sk, message);
    printf("proof = %s\n", proof);
    int verifyResult = curve25519_vrf_verify(pk, message, proof);
    printf("verifyResult = %d\n", verifyResult);
    char* hash = curve25519_vrf_proof_to_hash(proof);
    printf("hash = %s\n", hash);

    return 0;
}
