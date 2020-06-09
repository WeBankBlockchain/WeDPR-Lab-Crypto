#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <new>

static const int8_t FAILURE = -1;

static const int8_t SUCCESS = 0;

struct backtrace_state;

using backtrace_error_callback = void(*)(void *data, const char *msg, int errnum);

using backtrace_full_callback = int(*)(void *data, uintptr_t pc, const char *filename, int lineno, const char *function);

using backtrace_syminfo_callback = void(*)(void *data, uintptr_t pc, const char *symname, uintptr_t symval, uintptr_t symsize);

extern "C" {

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

char *curve25519_vrf_generate_key_pair(const char *private_key);

int8_t curve25519_vrf_is_valid_pubkey(const char *public_key);

char *curve25519_vrf_proof(const char *private_key, const char *alpha);

char *curve25519_vrf_proof_to_hash(const char *proof);

int8_t curve25519_vrf_verify(const char *public_key, const char *alpha, const char *proof);

} // extern "C"
