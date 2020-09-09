#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define FAILURE -1

#define SUCCESS 0

typedef struct backtrace_state backtrace_state;

typedef void (*backtrace_error_callback)(void *data, const char *msg, int errnum);

typedef int (*backtrace_full_callback)(void *data, uintptr_t pc, const char *filename, int lineno, const char *function);

typedef void (*backtrace_syminfo_callback)(void *data, uintptr_t pc, const char *symname, uintptr_t symval, uintptr_t symsize);

backtrace_state *__rbt_backtrace_create_state(const char *_filename,
                                              int _threaded,
                                              backtrace_error_callback _error,
                                              void *_data);

int __rbt_backtrace_pcinfo(backtrace_state *_state,
                           uintptr_t _addr,
                           backtrace_full_callback _cb,
                           backtrace_error_callback _error,
                           void *_data);

int __rbt_backtrace_syminfo(backtrace_state *_state,
                            uintptr_t _addr,
                            backtrace_syminfo_callback _cb,
                            backtrace_error_callback _error,
                            void *_data);

char *ecies_secp256k1_decrypt_c(char *hex_private_key, char *hex_ciphertext);

char *ecies_secp256k1_encrypt_c(char *hex_public_key, char *hex_plaintext);

char *wedpr_crypto_secp256k1Sign(char *hex_private_key, char *message_string);

char *wedpr_keccak256(char *message_string);

char *wedpr_secp256k1keyPair(void);

int8_t wedpr_secp256k1verify(char *hex_public_key, char *message_string, char *signature_string);
