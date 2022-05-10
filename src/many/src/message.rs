pub mod error;
pub mod request;
pub mod response;

use std::collections::BTreeMap;

use coset::SignatureContext;
use coset::cbor::value::Value;
use coset::iana::Algorithm;
use coset::CborSerializable;
use coset::CoseKeySet;
use coset::CoseSign1;
use coset::CoseSign1Builder;
use coset::HeaderBuilder;
use coset::Label;
use coset::ProtectedHeader;
pub use error::ManyError;
use minicbor::Decode;
pub use request::RequestMessage;
pub use request::RequestMessageBuilder;
pub use response::ResponseMessage;
pub use response::ResponseMessageBuilder;
use serde::Deserialize;
use sha2::Digest;

use crate::cose_helpers::public_key;
use crate::types::identity::cose::{CoseKeyIdentity, CoseKeyIdentitySignature};
use crate::Identity;
use signature::{Signature, Signer, Verifier};
use tracing::error;

#[derive(Deserialize)]
struct ClientData {
    challenge: String,
    #[allow(dead_code)]
    origin: String,
    r#type: String,
}

#[derive(Clone, Decode)]
#[cbor(map)]
struct WebAuthnChallenge {
    #[n(0)]
    header: Vec<u8>,

    #[n(1)]
    request_message: RequestMessage,
}

pub fn decode_request_from_cose_sign1(sign1: CoseSign1) -> Result<RequestMessage, ManyError> {
    let request = CoseSign1RequestMessage {
        sign1: sign1.clone(),
    };
    let unprotected = BTreeMap::from_iter(sign1.unprotected.rest.clone().into_iter());
    let is_webauthn = unprotected.contains_key(&Label::Text("webauthn".to_string()));
    request.verify(is_webauthn).ok();
    // let from_id = request.verify(is_webauthn).map_err(|e| {
    //     error!("e {}", e);
    //     ManyError::could_not_verify_signature()
    // })?;

    let message = if is_webauthn {
        tracing::trace!("Getting `clientDataStr` from unprotected header");
        let client_data = unprotected
            .get(&Label::Text("clientDataStr".to_string()))
            .ok_or_else(|| ManyError::required_field_missing("clientDataStr".to_string()))?
            .as_text()
            .ok_or_else(|| {
                ManyError::deserialization_error("clientDataStr is not Text".to_string())
            })?;
        let client_data_json: ClientData = serde_json::from_str(client_data)
            .map_err(|e| ManyError::deserialization_error(e.to_string()))?;

        tracing::trace!("Getting `authData` from unprotected header");
        let auth_data = unprotected
            .get(&Label::Text("authData".to_string()))
            .ok_or_else(|| ManyError::required_field_missing("authData".to_string()))?
            .as_bytes()
            .ok_or_else(|| ManyError::deserialization_error("authData is not Bytes".to_string()))?;

        tracing::trace!("Concatenating `authData` and sha256(`clientData`)");
        let mut msg = auth_data.clone();
        msg.extend(sha2::Sha256::digest(client_data));

        let cose_sig = CoseKeyIdentitySignature::from_bytes(&sign1.signature)
            .map_err(|e| ManyError::unknown(e.to_string()))?;

        let key_id = &sign1.unprotected.key_id;
        let from_id = Identity::from_bytes(&key_id).unwrap();
        let key = request
            .get_public_key_for_identity(&from_id, is_webauthn)
            .ok_or_else(|| ManyError::public_key_missing())?;
        tracing::trace!("Verifying WebAuthn signature");
        dbg!(&hex::encode(&msg));
        key.verify(&msg, &cose_sig)
            .map_err(|_| ManyError::could_not_verify_signature())?;

        tracing::trace!("Decoding base64 challenge");
        let challenge = base64::decode_config(client_data_json.challenge, base64::URL_SAFE_NO_PAD)
            .map_err(|e| ManyError::deserialization_error(e.to_string()))?;
        let challenge: WebAuthnChallenge = minicbor::decode(&challenge)
            .map_err(|e| ManyError::deserialization_error(e.to_string()))?;
        let protected_header = ProtectedHeader::from_cbor_bstr(Value::from(challenge.header))
            .map_err(|e| ManyError::deserialization_error(e.to_string()))?;

        // Check that key_id are the same
        if protected_header.header.key_id != sign1.unprotected.key_id {
            return Err(ManyError::invalid_key_id(
                hex::encode(protected_header.header.key_id),
                hex::encode(sign1.unprotected.key_id),
            ));
        }

        // Check that keyset are the same

        challenge.request_message
    } else {
        let payload = request
            .sign1
            .payload
            .ok_or_else(ManyError::empty_envelope)?;
        RequestMessage::from_bytes(&payload).map_err(ManyError::deserialization_error)?
    };

    // Check the `from` field.
    // if from_id != message.from.unwrap_or_default() {
    //     return Err(ManyError::invalid_from_identity());
    // }

    // We don't check the `to` field, leave that to the server itself.
    // Some servers might want to proxy messages that aren't for them, for example, or
    // accept anonymous messages.

    Ok(message)
}

pub fn decode_response_from_cose_sign1(
    sign1: CoseSign1,
    to: Option<Identity>,
) -> Result<ResponseMessage, String> {
    let request = CoseSign1RequestMessage { sign1 };
    let from_id = request.verify(false)?;

    let payload = request
        .sign1
        .payload
        .ok_or_else(|| "Envelope does not have payload.".to_string())?;
    let message = ResponseMessage::from_bytes(&payload)?;

    // Check the `from` field.
    if from_id != message.from {
        return Err("The message's from field does not match the envelope.".to_string());
    }

    // Check the `to` field to make sure we have the right one.
    if let Some(to_id) = to {
        if to_id != message.to.unwrap_or_default() {
            return Err("The message's to field is not for this server.".to_string());
        }
    }

    Ok(message)
}

fn encode_cose_sign1_from_payload(
    payload: Vec<u8>,
    cose_key: &CoseKeyIdentity,
) -> Result<CoseSign1, String> {
    let mut protected = HeaderBuilder::new()
        .algorithm(Algorithm::EdDSA)
        .key_id(cose_key.identity.to_vec());

    // Add the keyset to the headers.
    if let Some(key) = cose_key.key.as_ref() {
        let mut keyset = CoseKeySet::default();
        let mut key_public = public_key(key)?;
        key_public.key_id = cose_key.identity.to_vec();
        keyset.0.push(key_public);

        protected = protected.text_value(
            "keyset".to_string(),
            Value::Bytes(keyset.to_vec().map_err(|e| e.to_string())?),
        );
    }

    let protected = protected.build();

    let mut cose_builder = CoseSign1Builder::default()
        .protected(protected)
        .payload(payload);

    if cose_key.key.is_some() {
        cose_builder = cose_builder
            .try_create_signature(b"", |msg| {
                cose_key
                    .try_sign(msg)
                    .map(|v| v.as_bytes().to_vec())
                    .map_err(|e| e.to_string())
            })
            .map_err(|e| e)?;
    }
    Ok(cose_builder.build())
}

pub fn encode_cose_sign1_from_response(
    response: ResponseMessage,
    cose_key: &CoseKeyIdentity,
) -> Result<CoseSign1, String> {
    encode_cose_sign1_from_payload(
        response
            .to_bytes()
            .map_err(|e| format!("Could not serialize response: {}", e))?,
        cose_key,
    )
}

pub fn encode_cose_sign1_from_request(
    request: RequestMessage,
    cose_key: &CoseKeyIdentity,
) -> Result<CoseSign1, String> {
    encode_cose_sign1_from_payload(request.to_bytes().unwrap(), cose_key)
}

/// Provide utility functions surrounding request and response messages.
#[derive(Clone, Debug, Default)]
pub(crate) struct CoseSign1RequestMessage {
    pub sign1: CoseSign1,
}

impl CoseSign1RequestMessage {
    pub fn get_keyset(&self, is_webauthn: bool) -> Option<CoseKeySet> {
        let header = if is_webauthn {
            &self.sign1.unprotected
        } else {
            &self.sign1.protected.header
        };

        let keyset = header
            .rest
            .iter()
            .find(|(k, _)| k == &Label::Text("keyset".to_string()))?
            .1
            .clone();

        if let Value::Bytes(ref bytes) = keyset {
            CoseKeySet::from_slice(bytes).ok()
        } else {
            None
        }
    }

    pub fn get_public_key_for_identity(
        &self,
        id: &Identity,
        is_webauthn: bool,
    ) -> Option<CoseKeyIdentity> {
        // Verify the keybytes matches the identity.
        if id.is_anonymous() {
            return None;
        }

        let cose_key = self
            .get_keyset(is_webauthn)?
            .0
            .into_iter()
            .find(|key| id.matches_key(Some(key)))?; // TODO: We might want to optimize this for lookup?

        // The hsm: false parameter is not important here. We always perform
        // signature verification on the CPU server-side
        let key = CoseKeyIdentity::from_key(cose_key, false).ok()?;
        if id == &key.identity {
            Some(key)
        } else {
            None
        }
    }

    pub fn verify(&self, is_webauthn: bool) -> Result<Identity, String> {
        let header = if is_webauthn {
            &self.sign1.unprotected
        } else {
            &self.sign1.protected.header
        };

        if !header.key_id.is_empty() {
            if let Ok(id) = Identity::from_bytes(&header.key_id) {
                if id.is_anonymous() {
                    return Ok(id);
                }

                tracing::trace!("PAYLOAD: {}", hex::encode(&self.sign1.payload.as_ref().unwrap()));
                self.get_public_key_for_identity(&id, is_webauthn)
                    .ok_or_else(|| ManyError::public_key_missing().to_string())
                    .and_then(|key| {
                        self.sign1
                            .verify_signature(b"", |sig, content| {
                                let sig = CoseKeyIdentitySignature::from_bytes(sig).unwrap();
                                key.verify(&content, &sig)
                            })
                            .map_err(|e| e.to_string())?;
                        Ok(id)
                    })
            } else {
                Err("Invalid (not a MANY identity) key ID".to_string())
            }
        } else {
            if self.sign1.signature.is_empty() {
                return Ok(Identity::anonymous());
            }

            Err("Missing key ID".to_string())
        }
    }
}
