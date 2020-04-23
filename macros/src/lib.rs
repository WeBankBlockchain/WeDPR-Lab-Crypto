pub const ENABLE_DEBUG_OUTPUT: bool = true;

#[macro_export]
macro_rules! wedpr_println {
            () => ( print!("\n"));
            ($($arg:tt)*) => {
            if $crate::ENABLE_DEBUG_OUTPUT {
                      print!("{}:{}: ", file!(), line!());
                      println!($($arg)*);
            }
     };
}

#[macro_export]
macro_rules! string_to_point {
    ($param:expr) => {
        match utils::string_to_point($param) {
            Ok(v) => v,
            Err(_) => {
                wedpr_println!("macro string_to_point failed");
                return false;
            },
        }
    };
}

#[macro_export]
macro_rules! string_to_scalar {
    ($param:expr) => {
        match utils::string_to_scalar($param) {
            Ok(v) => v,
            Err(_) => {
                wedpr_println!("macro string_to_scalar failed");
                return false;
            },
        }
    };
}
