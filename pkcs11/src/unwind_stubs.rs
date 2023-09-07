#[no_mangle]
pub extern "C" fn _Unwind_Resume() {}

#[no_mangle]
pub extern "C" fn _Unwind_GetTextRelBase() {}

#[no_mangle]
pub extern "C" fn _Unwind_GetIPInfo() {}

#[no_mangle]
pub extern "C" fn _Unwind_GetIP() {}

#[no_mangle]
pub extern "C" fn _Unwind_SetGR() {}

#[no_mangle]
pub extern "C" fn _Unwind_GetLanguageSpecificData() {}

#[no_mangle]
pub extern "C" fn _Unwind_Backtrace() {}

#[no_mangle]
pub extern "C" fn _Unwind_GetRegionStart() {}

#[no_mangle]
pub extern "C" fn _Unwind_SetIP() {}

#[no_mangle]
pub extern "C" fn _Unwind_GetDataRelBase() {}
