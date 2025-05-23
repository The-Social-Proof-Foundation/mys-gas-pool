// Copyright (c) Mysten Labs, Inc.
// Copyright (c) The Social Proof Foundation, LLC.
// SPDX-License-Identifier: Apache-2.0

use crate::types::ReservationID;
use fastcrypto::encoding::Base64;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use mys_json_rpc_types::{MysObjectRef, MysTransactionBlockEffects};
use mys_types::base_types::{ObjectRef, MysAddress};

// 2 MYS.
pub const MAX_BUDGET: u64 = 2_000_000_000;

// 10 mins.
pub const MAX_DURATION_S: u64 = 10 * 60;

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct ReserveGasRequest {
    pub gas_budget: u64,
    pub reserve_duration_secs: u64,
}

impl ReserveGasRequest {
    pub fn check_validity(&self) -> anyhow::Result<()> {
        if self.gas_budget == 0 {
            anyhow::bail!("Gas budget must be positive");
        }
        if self.gas_budget > MAX_BUDGET {
            anyhow::bail!("Gas budget must be less than {}", MAX_BUDGET);
        }
        if self.reserve_duration_secs == 0 {
            anyhow::bail!("Reserve duration must be positive");
        }
        if self.reserve_duration_secs > MAX_DURATION_S {
            anyhow::bail!(
                "Reserve duration must be less than {} seconds",
                MAX_DURATION_S
            );
        }
        Ok(())
    }
}

#[derive(Debug, JsonSchema, Serialize, Deserialize)]
pub struct ReserveGasResponse {
    pub result: Option<ReserveGasResult>,
    pub error: Option<String>,
}

#[derive(Debug, JsonSchema, Serialize, Deserialize)]
pub struct ReserveGasResult {
    pub sponsor_address: MysAddress,
    pub reservation_id: ReservationID,
    pub gas_coins: Vec<MysObjectRef>,
}

impl ReserveGasResponse {
    pub fn new_ok(
        sponsor_address: MysAddress,
        reservation_id: ReservationID,
        gas_coins: Vec<ObjectRef>,
    ) -> Self {
        Self {
            result: Some(ReserveGasResult {
                sponsor_address,
                reservation_id,
                gas_coins: gas_coins.into_iter().map(|c| c.into()).collect(),
            }),
            error: None,
        }
    }

    pub fn new_err(error: anyhow::Error) -> Self {
        Self {
            result: None,
            error: Some(error.to_string()),
        }
    }
}

#[derive(Debug, JsonSchema, Serialize, Deserialize)]
pub struct ExecuteTxRequest {
    pub reservation_id: ReservationID,
    pub tx_bytes: Base64,
    pub user_sig: Base64,
}

#[derive(Debug, JsonSchema, Serialize, Deserialize)]
pub struct ExecuteTxResponse {
    pub effects: Option<MysTransactionBlockEffects>,
    pub error: Option<String>,
}

impl ExecuteTxResponse {
    pub fn new_ok(effects: MysTransactionBlockEffects) -> Self {
        Self {
            effects: Some(effects),
            error: None,
        }
    }

    pub fn new_err(error: anyhow::Error) -> Self {
        Self {
            effects: None,
            error: Some(error.to_string()),
        }
    }
}
