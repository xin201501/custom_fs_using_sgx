// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License..

use sgx_types::{error::SgxStatus, types::EnclaveId};
use sgx_urts::enclave::SgxEnclave;
extern "C" {
    fn sample(eid: EnclaveId, ret: *mut SgxStatus);
}

fn test_sample() -> anyhow::Result<()> {
    // create an enclave
    let enclave = SgxEnclave::create("../bin/enclave.signed.so", true)?;
    let mut sgx_status = SgxStatus::BadStatus;
    unsafe { sample(enclave.eid(), &mut sgx_status) };
    // match `sgx_status`
    match sgx_status {
        SgxStatus::Success => Ok(()),
        _ => Err(anyhow::anyhow!(
            "enclave run failed with status: {:?}",
            sgx_status
        )),
    }
}
#[test]
fn test() {
    test_sample().unwrap();
}
