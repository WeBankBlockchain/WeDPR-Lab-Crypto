#[macro_use]
extern crate wedpr_macros;
#[macro_use]
extern crate ffi_macros;

use crypto::curve_25519_vrf;
use crypto::curve_25519_vrf::vrf_proof;
use ffi_common::utils;
use libc::c_char;
use std::ffi::CString;
use std::ptr;
use std::{ffi::CStr, panic};

pub const SUCCESS: i8 = 0;
pub const FAILURE: i8 = -1;

#[allow(non_camel_case_types)]
pub mod backtrace_hack {

    extern crate libc;

    use self::libc::uintptr_t;
    use std::os::raw::{c_char, c_int, c_void};

    pub type backtrace_syminfo_callback = extern "C" fn(
        data: *mut c_void,
        pc: uintptr_t,
        symname: *const c_char,
        symval: uintptr_t,
        symsize: uintptr_t,
    );
    pub type backtrace_full_callback = extern "C" fn(
        data: *mut c_void,
        pc: uintptr_t,
        filename: *const c_char,
        lineno: c_int,
        function: *const c_char,
    ) -> c_int;
    pub type backtrace_error_callback =
        extern "C" fn(data: *mut c_void, msg: *const c_char, errnum: c_int);
    pub enum backtrace_state {}

    #[no_mangle]
    pub extern "C" fn __rbt_backtrace_create_state(
        _filename: *const c_char,
        _threaded: c_int,
        _error: backtrace_error_callback,
        _data: *mut c_void,
    ) -> *mut backtrace_state {
        0 as *mut _
    }

    #[no_mangle]
    pub extern "C" fn __rbt_backtrace_syminfo(
        _state: *mut backtrace_state,
        _addr: uintptr_t,
        _cb: backtrace_syminfo_callback,
        _error: backtrace_error_callback,
        _data: *mut c_void,
    ) -> c_int {
        0
    }

    #[no_mangle]
    pub extern "C" fn __rbt_backtrace_pcinfo(
        _state: *mut backtrace_state,
        _addr: uintptr_t,
        _cb: backtrace_full_callback,
        _error: backtrace_error_callback,
        _data: *mut c_void,
    ) -> c_int {
        0
    }
}

#[no_mangle]
pub extern "C" fn curve25519_vrf_generate_key_pair(private_key: *const c_char) -> *mut c_char {
    let result = panic::catch_unwind(|| {
        let sk = match utils::c_char_to_string(private_key) {
            Ok(v) => v,
            Err(_) => {
                wedpr_println!("private_key c_char_to_string failed!");
                return ptr::null_mut();
            }
        };

        let encrypt_data = curve_25519_vrf::curve25519_vrf_gen_pubkey(&sk);

        let return_string = match CString::new(encrypt_data) {
            Ok(v) => v,
            Err(_) => return ptr::null_mut(),
        };
        return_string.into_raw()
    });
    match result {
        Ok(res) => res,
        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn curve25519_vrf_proof(
    private_key: *const c_char,
    alpha: *const c_char,
) -> *mut c_char {
    let result = panic::catch_unwind(|| {
        let sk = match utils::c_char_to_string(private_key) {
            Ok(v) => v,
            Err(_) => {
                wedpr_println!("private_key c_char_to_string failed!");
                return ptr::null_mut();
            }
        };

        let message = match utils::c_char_to_string(alpha) {
            Ok(v) => v,
            Err(_) => {
                wedpr_println!("alpha c_char_to_string failed!");
                return ptr::null_mut();
            }
        };

        let proof = match curve_25519_vrf::curve25519_vrf_prove(&sk, &message) {
            Ok(v) => v,
            Err(_) => {
                wedpr_println!("curve25519_vrf_prove failed!");
                return ptr::null_mut();
            }
        };

        let return_string = match CString::new(proof.encode()) {
            Ok(v) => v,
            Err(_) => return ptr::null_mut(),
        };
        return_string.into_raw()
    });
    match result {
        Ok(res) => res,
        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn curve25519_vrf_verify(
    public_key: *const c_char,
    alpha: *const c_char,
    proof: *const c_char,
) -> i8 {
    let result = panic::catch_unwind(|| {
        let pk = match utils::c_char_to_string(public_key) {
            Ok(v) => v,
            Err(_) => {
                wedpr_println!("public_key c_char_to_string failed!");
                return FAILURE;
            }
        };

        let message = match utils::c_char_to_string(alpha) {
            Ok(v) => v,
            Err(_) => {
                wedpr_println!("alpha c_char_to_string failed!");
                return FAILURE;
            }
        };

        let vrf_proof = match utils::c_char_to_string(proof) {
            Ok(v) => v,
            Err(_) => {
                wedpr_println!("proof c_char_to_string failed!");
                return FAILURE;
            }
        };

        let decode_proof = match vrf_proof::decode(&vrf_proof) {
            Ok(v) => v,
            Err(_) => {
                wedpr_println!("decode proof failed!, vrf_proof = {}", vrf_proof);
                return FAILURE;
            }
        };
        let proof = curve_25519_vrf::curve25519_vrf_verify(&pk, &message, &decode_proof);
        if proof == false {
            return FAILURE;
        }
        SUCCESS
    });
    match result {
        Ok(res) => res,
        Err(_) => FAILURE,
    }
}

#[no_mangle]
pub extern "C" fn curve25519_vrf_is_valid_pubkey(public_key: *const c_char) -> i8 {
    let result = panic::catch_unwind(|| {
        let pk = match utils::c_char_to_string(public_key) {
            Ok(v) => v,
            Err(_) => {
                wedpr_println!("public_key c_char_to_string failed!");
                return FAILURE;
            }
        };

        let proof = curve_25519_vrf::curve25519_vrf_is_valid_pubkey(&pk);
        if proof == false {
            return FAILURE;
        }
        SUCCESS
    });
    match result {
        Ok(res) => res,
        Err(_) => FAILURE,
    }
}

#[no_mangle]
pub extern "C" fn curve25519_vrf_proof_to_hash(proof: *const c_char) -> *mut c_char {
    let result = panic::catch_unwind(|| {
        let vrf_proof = match utils::c_char_to_string(proof) {
            Ok(v) => v,
            Err(_) => {
                wedpr_println!("proof c_char_to_string failed!");
                return ptr::null_mut();
            }
        };

        let decode_proof = match vrf_proof::decode(&vrf_proof) {
            Ok(v) => v,
            Err(_) => {
                wedpr_println!("decode proof failed!, vrf_proof = {}", vrf_proof);
                return ptr::null_mut();
            }
        };

        let hash = match curve_25519_vrf::curve25519_vrf_proof_to_hash(&decode_proof) {
            Ok(v) => v,
            Err(_) => {
                wedpr_println!("curve25519_vrf_prove failed!");
                return ptr::null_mut();
            }
        };

        let return_string = match CString::new(hash) {
            Ok(v) => v,
            Err(_) => return ptr::null_mut(),
        };
        return_string.into_raw()
    });
    match result {
        Ok(res) => res,
        Err(_) => ptr::null_mut(),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
