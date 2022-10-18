use crate::client::send_envelope as send_envelope_async;
use coset::CoseSign1;
use many_identity::{Address, Identity};
use many_modules::base::Status;
use many_protocol::{RequestMessage, ResponseMessage};
use many_server::ManyError;
use minicbor::Encode;
use once_cell::sync::OnceCell;
use reqwest::IntoUrl;

use crate::ManyClient as AsyncClient;

#[derive(Debug, Clone)]
pub struct ManyClient<I: Identity> {
    client: AsyncClient<I>,
}

static RUNTIME: OnceCell<tokio::runtime::Runtime> = OnceCell::new();

pub fn block_on<F>(future: F) -> F::Output
where
    F: std::future::Future,
{
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => tokio::task::block_in_place(|| handle.block_on(future)),
        Err(_) => {
            let runtime = RUNTIME.get_or_init(|| tokio::runtime::Runtime::new().unwrap());
            runtime.block_on(future)
        }
    }
}

pub fn send_envelope<S: IntoUrl>(url: S, message: CoseSign1) -> Result<CoseSign1, ManyError> {
    block_on(send_envelope_async(url, message))
}

impl<I: Identity> ManyClient<I> {
    pub fn new<S: IntoUrl>(url: S, to: Address, identity: I) -> Result<Self, String> {
        let client = AsyncClient::new(url, to, identity)?;
        Ok(Self { client })
    }

    pub fn send_message(&self, message: RequestMessage) -> Result<ResponseMessage, ManyError> {
        block_on(self.client.send_message(message))
    }

    pub fn call_raw<M>(&self, method: M, argument: &[u8]) -> Result<ResponseMessage, ManyError>
    where
        M: Into<String>,
    {
        block_on(self.client.call_raw(method, argument))
    }

    pub fn call<M, A>(&self, method: M, argument: A) -> Result<ResponseMessage, ManyError>
    where
        M: Into<String>,
        A: Encode<()>,
    {
        block_on(self.client.call(method, argument))
    }

    pub fn call_<M, A>(&self, method: M, argument: A) -> Result<Vec<u8>, ManyError>
    where
        M: Into<String>,
        A: Encode<()>,
    {
        block_on(self.client.call_(method, argument))
    }

    pub fn status(&self) -> Result<Status, ManyError> {
        block_on(self.client.status())
    }
}
