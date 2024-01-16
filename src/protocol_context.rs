// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crypto_bigint::U128;
use serde::{Deserialize, Serialize};

use crate::PartyID;

#[derive(Clone, Serialize, Deserialize, PartialEq, Debug, Eq)]
enum Party {
    CentralizedParty,
    DecentralizedParty(PartyID),
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Debug, Eq)]
enum Protocol {
    TWOPCMPC(SubProtocol),
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Debug, Eq)]
enum SubProtocol {
    DKG,
    Presign,
    Sign,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Debug, Eq)]
enum Signature {
    ECDSA,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Debug, Eq)]
struct ProtocolContext<EmbeddingProtocolContext> {
    party: Party,
    // TODO: size, and whether it should depend on security parameters.
    session_id: U128,
    protocol: Protocol,
    signature: Signature,
    // TODO: we said we want to put in the library version; I'm not sure about this, as
    // incompatabilities may arise, and I'm not sure we want to fail in these cases.
    round_name: String,
    proof_index: String,
    // TODO: what type
    embedding_protocol_context: EmbeddingProtocolContext,
}

impl<EmbeddingProtocolContext> ProtocolContext<EmbeddingProtocolContext> {
    fn new(
        party: Party,
        session_id: U128,
        protocol: Protocol,
        round_name: String,
        proof_index: String,
        embedding_protocol_context: EmbeddingProtocolContext,
    ) -> Self {
        Self {
            party,
            session_id,
            protocol,
            signature: Signature::ECDSA,
            round_name,
            proof_index,
            embedding_protocol_context,
        }
    }

    fn with_party(self, party: Party) -> Self {
        Self { party, ..self }
    }
}

#[cfg(test)]
mod tests {
    use crypto_bigint::Random;
    use rand_core::OsRng;

    use super::*;

    #[derive(Clone, Serialize, Deserialize, PartialEq, Debug, Eq)]
    struct EmbeddingContext {
        name: String,
    }

    #[test]
    fn serializes() {
        let session_id = U128::from_le_hex("bee3ce424096c7c74ef0dbd8df858ecb");

        let embedding_protocol_context = EmbeddingContext {
            name: "slim-shady".to_string(),
        };

        let protocol_context = ProtocolContext::new(
            Party::CentralizedParty,
            session_id,
            Protocol::TWOPCMPC(SubProtocol::DKG),
            "commitment round".to_string(),
            "gamma".to_string(),
            embedding_protocol_context,
        );

        assert_eq!(
            serde_json::to_string_pretty(&protocol_context).unwrap(),
            "{\n  \
            \"party\": \"CentralizedParty\",\n  \
            \"session_id\": \"bee3ce424096c7c74ef0dbd8df858ecb\",\n  \
            \"protocol\": {\n    \"TWOPCMPC\": \"DKG\"\n  },\n  \
            \"signature\": \"ECDSA\",\n  \
            \"round_name\": \"commitment round\",\n  \
            \"proof_index\": \"gamma\",\n  \
            \"embedding_protocol_context\": {\n    \"name\": \"slim-shady\"\n  }\n\
            }"
        );

        assert_eq!(
            serde_json::to_string_pretty(
                &protocol_context.with_party(Party::DecentralizedParty(42))
            )
            .unwrap(),
            "{\n  \
            \"party\": {\n    \"DecentralizedParty\": 42\n  },\n  \
            \"session_id\": \"bee3ce424096c7c74ef0dbd8df858ecb\",\n  \
            \"protocol\": {\n    \"TWOPCMPC\": \"DKG\"\n  },\n  \
            \"signature\": \"ECDSA\",\n  \
            \"round_name\": \"commitment round\",\n  \
            \"proof_index\": \"gamma\",\n  \
            \"embedding_protocol_context\": {\n    \"name\": \"slim-shady\"\n  }\n\
            }"
        );
    }
}
