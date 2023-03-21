#[cfg(test)]
mod tests {
    use sgx_types::{error::SgxStatus, types::EnclaveId};
    use sgx_urts::enclave::SgxEnclave;

    use crate::sgx_components::DEFAULT_ENCLAVE_PATH;

    extern "C" {
        fn test_third_party_crates(eid: EnclaveId) -> SgxStatus;
    }

    // test third party crates work in sgx as well
    #[test]
    fn test_sgx_third_party_crates() -> anyhow::Result<()> {
        //create an enclave
        let enclave = SgxEnclave::create(DEFAULT_ENCLAVE_PATH, true)?;
        let status = unsafe { test_third_party_crates(enclave.eid()) };
        match status {
            SgxStatus::Success => Ok(()),
            _ => Err(anyhow::anyhow!("test_failed")),
        }
    }
}
