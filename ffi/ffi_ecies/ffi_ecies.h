#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <new>

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

char *ecies_secp256k1_decrypt_c(char *hex_private_key, char *hex_encrypt_data);

char *ecies_secp256k1_encrypt_c(char *hex_public_key, char *hex_message);

} // extern "C"
