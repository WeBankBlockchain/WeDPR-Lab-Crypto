#include <stdlib.h>
#include "ffi_ecies.h"
#include <stdio.h>
int main()
{
    char* pk = "0436f3570c796c7589a150a4d8a3de37cef15f30e141ca9a7e3162d9c2e3edb4e8db2326fe5489fdbe4ce7931779b727242f7df19c0a773f101417616e7776e789";
    char* sk = "e82a0751b7671d20d24631faa7033ee6909ed73629e1795e830b8fb8666e17b8";
    char* message = "847adcf9b24cf0041ddff02ffe324e30b1271c5170086f8ee799dd1123dacb2e";
    char* encryptData = ecies_secp256k1_encrypt_c(pk, message);
    printf("encryptData = %s", encryptData);
    char* decryptData = ecies_secp256k1_decrypt_c(sk, encryptData);
    printf("decryptData = %s", decryptData);
    
    // cout << "decryptData = " << decryptData << endl;
    return 0;
}
