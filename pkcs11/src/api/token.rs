use log::trace;


pub extern "C" fn C_GetSlotList(
  tokenPresent: cryptoki_sys ::CK_BBOOL,
  pSlotList: cryptoki_sys::CK_SLOT_ID_PTR,
  pulCount: cryptoki_sys ::CK_ULONG_PTR,
) -> cryptoki_sys::CK_RV {

  trace!("C_GetSlotList() called");

  cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}