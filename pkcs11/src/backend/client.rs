use log::error;

use crate::data::CLIENTS;

pub fn get_client(
    slot_id: usize,
) -> Result<openapi::apis::configuration::Configuration, cryptoki_sys::CK_RV> {
    let clients = CLIENTS.read().map_err(|e| {
        error!("Error reading clients: {:?}", e);
        cryptoki_sys::CKR_FUNCTION_FAILED
    })?;
    clients
        .get(slot_id)
        .ok_or_else(|| {
            error!("No client found for slotID: {}", slot_id);
            cryptoki_sys::CKR_SLOT_ID_INVALID
        })
        .map(|client| client.clone())
}
