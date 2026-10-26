use super::*;

#[test]
fn input_is_borrowed_and_invalid_descriptors_are_rejected() {
    let bytes = [7u8; 32];
    let input = CInputBuffer {
        data: bytes.as_ptr().cast(),
        len: bytes.len(),
    };
    let borrowed = unsafe { c_read_raw_pointer(&input).unwrap() };
    assert_eq!(borrowed.as_ptr(), bytes.as_ptr());
    assert_eq!(borrowed, &bytes);
    let empty = CInputBuffer {
        data: std::ptr::null(),
        len: 0,
    };
    assert!(unsafe { c_read_raw_pointer(&empty).unwrap() }.is_empty());
    let invalid = CInputBuffer {
        data: std::ptr::null(),
        len: 1,
    };
    assert!(unsafe { c_read_raw_pointer(&invalid) }.is_err());
    let oversized = CInputBuffer {
        data: bytes.as_ptr().cast(),
        len: usize::MAX,
    };
    assert!(unsafe { c_read_raw_pointer(&oversized) }.is_err());
}

#[test]
fn short_or_null_output_never_writes_or_panics() {
    let bytes = [1u8, 2, 3];
    let mut destination = [99u8; 4];
    let mut output = COutputBuffer {
        data: destination.as_mut_ptr().cast(),
        len: 2,
    };
    assert!(unsafe { c_write_raw_pointer(&bytes, &mut output) }.is_err());
    assert_eq!(output.len, 3);
    assert_eq!(destination, [99u8; 4]);
    assert!(unsafe { c_write_raw_pointer(&bytes, &mut output) }.is_ok());
    assert_eq!(destination, [1, 2, 3, 99]);
    let mut null = COutputBuffer {
        data: std::ptr::null_mut(),
        len: 3,
    };
    assert!(unsafe { c_write_raw_pointer(&bytes, &mut null) }.is_err());
    assert!(unsafe { c_write_raw_pointer(&[], &mut null) }.is_ok());
    assert_eq!(null.len, 0);
}

#[test]
fn null_c_string_returns_an_error() {
    assert!(unsafe { c_char_pointer_to_string(std::ptr::null()) }.is_err());
    assert!(unsafe { c_char_pointer_to_bytes(std::ptr::null()) }.is_err());
}

#[test]
fn null_or_unaligned_descriptors_are_rejected_before_reference_creation() {
    assert!(unsafe { c_copy_input_buffer(std::ptr::null()) }.is_err());
    assert!(unsafe { c_borrow_output_buffer(std::ptr::null_mut()) }.is_err());
    assert!(
        unsafe { c_copy_input_buffer(1usize as *const CInputBuffer) }.is_err()
    );
    assert!(
        unsafe { c_borrow_output_buffer(1usize as *mut COutputBuffer) }
            .is_err()
    );
}
