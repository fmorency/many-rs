use crate::server::module::EmptyReturn;
use crate::{Identity, ManyError};
use many_macros::many_module;

#[cfg(test)]
use mockall::{automock, predicate::*};

mod send;

pub use send::*;

#[many_module(name = LedgerCommandsModule, id = 6, namespace = ledger, many_crate = crate)]
#[cfg_attr(test, automock)]
pub trait LedgerCommandsModuleBackend: Send {
    fn send(&mut self, sender: &Identity, args: SendArgs) -> Result<EmptyReturn, ManyError>;
}

#[cfg(test)]
mod tests {
    use std::{
        str::FromStr,
        sync::{Arc, Mutex},
    };

    use crate::{server::module::testutils::{call_module_cbor}, types::ledger::TokenAmount};

    use super::*;

    #[test]
    fn send() {
        let mut mock = MockLedgerCommandsModuleBackend::new();
        mock.expect_send()
            .times(1)
            .returning(|_sender, _args| Ok(EmptyReturn));
        let module = super::LedgerCommandsModule::new(Arc::new(Mutex::new(mock)));

        let data = SendArgs {
            from: Some(Identity::anonymous()),
            to: Identity::anonymous(),
            amount: TokenAmount::from(512u16),
            symbol: Identity::from_str("mqbfbahksdwaqeenayy2gxke32hgb7aq4ao4wt745lsfs6wiaaaaqnz")
                .unwrap(),
        };
        let _: EmptyReturn = minicbor::decode(
            &call_module_cbor(1, &module, "ledger.send", minicbor::to_vec(data).unwrap()).unwrap(),
        )
        .unwrap();
    }
}
