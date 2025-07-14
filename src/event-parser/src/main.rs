use std::collections::{BTreeMap, Bound};
use std::fs;
use std::fs::File;
use std::str::FromStr;
use anyhow::anyhow;
use chrono::{DateTime, Utc};
use clap::{Parser};
use csv::Writer;
use indicatif::ProgressBar;
use minicbor::{Decode, Encode};
use many_cli_helpers::error::ClientServerError;
use many_cli_helpers::error::ClientServerError::Client;
use many_client::client::blocking::ManyClient;
use many_identity::{Address, AnonymousIdentity, Identity};
use many_modules::events::{EventFilter, EventId};
use many_types::{CborRange, Memo, VecOrSingle};
use many_types::ledger::TokenAmount;

#[derive(Encode, Decode)]
struct CachedEvents {
    #[n(0)]
    events: Vec<many_modules::events::EventLog>,
}

#[derive(Parser)]
struct Opts {
    #[clap(flatten)]
    common_flags: many_cli_helpers::CommonCliFlags,

    /// Many server URL to connect to.
    #[clap(default_value = "http://localhost:8000")]
    servers: Vec<String>,

}


fn load_or_fetch_events(
    id: usize,
    client: ManyClient<impl Identity>
) -> Result<Vec<many_modules::events::EventLog>, ClientServerError> {
    let cache_file = format!("{}_events_cache.cbor", id);
    if let Ok(data) = fs::read(&cache_file) {
        println!("Loading events from cache: {}", &cache_file);
        if let Ok(cached) = minicbor::decode::<CachedEvents>(&data) {
            return Ok(cached.events);
        }
    }

    println!("Fetching events from server...");
    let events = _extract_events(client)?;
    let cached = CachedEvents { events };
    if let Ok(cbor) = minicbor::to_vec(&cached) {
        let _ = fs::write(cache_file, cbor);
    }
    Ok(cached.events)
}

fn _extract_events(
    client: ManyClient<impl Identity>,
    // identity: Option<String>,
) -> Result<Vec<many_modules::events::EventLog>, ClientServerError> {
    let mut filter = EventFilter::default();
    let event_count_result: many_modules::events::ListReturns = minicbor::decode(&client.call_("events.list", many_modules::events::ListArgs {
        count: Some(1),
        order: None,
        filter: None,
    })?)?;
    let total_event_count = event_count_result.nb_events;
    let pb = ProgressBar::new(total_event_count);

    let mut all_events = vec![];
    let mut last_id: Option<EventId> = None;
    loop {
        if let Some(last_id) = &last_id {
            filter.id_range = Some(CborRange {
                start: Bound::Excluded(last_id.clone()),
                end: Bound::Unbounded,
            });
        }
        let list: many_modules::events::ListReturns = minicbor::decode(&client.call_("events.list", many_modules::events::ListArgs {
            count: Some(100), // Adjust count as needed
            order: None,
            filter: Some(filter.clone()),
        })?)?;

        if list.events.is_empty() {
            break;
        }

        pb.inc(list.events.len() as u64);

        last_id = list.events.last().map(|e| e.id.clone());
        all_events.extend(list.events);
    }

    pb.finish_with_message(format!("Retrieved {} events", all_events.len()));

    Ok(all_events)
}

fn parse_balances(
    all_events: &Vec<many_modules::events::EventLog>,
    mfx: Address
) -> Result<(), ClientServerError> {
    let mut balances: BTreeMap<String, TokenAmount> = BTreeMap::from([("mqdjnydq6funtibfdehemay6lwirrgeroazmqqhhac2jaq5yaaaaayf".into(), TokenAmount::from(100_000_000__000_000_000u128))]);
    let mut to_add: BTreeMap<String, TokenAmount> = BTreeMap::new();
    let mut to_sub: BTreeMap<String, TokenAmount> = BTreeMap::new();

    for event in all_events {
        match &event.content {
            many_modules::events::EventInfo::TokenMint { symbol, distribution, .. } => {
                if symbol != &mfx {
                    continue;
                }
                for (account, amount) in distribution {
                    *to_add.entry(account.to_string()).or_insert(TokenAmount::from(0u8)) += amount;
                }
            },
            many_modules::events::EventInfo::TokenBurn { symbol, distribution, .. } => {
                if symbol != &mfx {
                    continue;
                }
                for (account, amount) in distribution {
                    *to_sub.entry(account.to_string()).or_insert(TokenAmount::from(0u8)) += amount;
                }
            },
            many_modules::events::EventInfo::Send { from, to, symbol, amount, .. } => {
                if symbol != &mfx {
                    continue;
                }
                *to_sub.entry(from.to_string()).or_insert(TokenAmount::from(0u8)) += amount.clone();
                *to_add.entry(to.to_string()).or_insert(TokenAmount::from(0u8)) += amount;
            },
            _ => {}
        }
    }

    for (address, amount) in to_add {
        *balances.entry(address).or_insert(TokenAmount::from(0u8)) += amount;
    }

    for (address, amount) in to_sub {
        *balances.entry(address).or_insert(TokenAmount::from(0u8)) -= amount;
    }

    let mut wtr = Writer::from_writer(File::create("balances.csv").map_err(|e| Client(anyhow!("Can't create CSV writer")))?);
    wtr.write_record(&["address", "amount"]).map_err(|e| Client(anyhow!("Can't write CSV header")))?;
    for (address, amount) in &balances {
        wtr.write_record(&[address, &amount.to_string()]).map_err(|e| Client(anyhow!("Can't write CSV record")))?;
    }
    wtr.flush().map_err(|e| Client(anyhow!("Can't flush CSV record")))?;

    Ok(())
}

fn parse_transactions(
    all_events: Vec<many_modules::events::EventLog>,
    mfx: Address,
) -> Result<(), ClientServerError> {
    let mut wtr = Writer::from_writer(File::create("transactions.csv").map_err(|e| Client(anyhow!("Can't create CSV writer")))?);
    wtr.write_record(&["date", "from", "to", "amount", "type", "memo"]).map_err(|e| Client(anyhow!("Can't write CSV header")))?;

    for event in all_events {
        let t = event.time.as_system_time()?;
        let dt: DateTime<Utc> = t.into();
        let iso_dt = dt.to_rfc3339();

        let k = event.kind().to_string();

        match event.content {
            many_modules::events::EventInfo::TokenMint { symbol, distribution, memo } => {
                if symbol != mfx {
                    continue;
                }

                let m = memo.unwrap_or(Memo::try_from("")?);
                let a: Vec<String> = m.iter_str().map(|s| s.to_string()).collect();
                let memo_str = if a.is_empty() {
                    "".to_string()
                }
                else {
                    format!("\"{}\"", a.join(" "))
                };

                for (account, amount) in distribution {
                    wtr.write_record(&[
                        iso_dt.clone(),
                        "".to_string(),
                        account.to_string(),
                        amount.to_string(),
                        k.clone(),
                        memo_str.clone(),
                    ]).map_err(|e| Client(anyhow!("Can't write CSV record")))?;
                }
            },
            many_modules::events::EventInfo::TokenBurn { symbol, distribution, memo } => {
                if symbol != mfx {
                    continue;
                }

                let m = memo.unwrap_or(Memo::try_from("")?);
                let a: Vec<String> = m.iter_str().map(|s| s.to_string()).collect();
                let memo_str = if a.is_empty() {
                    "".to_string()
                }
                else {
                    format!("\"{}\"", a.join(" "))
                };

                for (account, amount) in distribution {
                    wtr.write_record(&[
                        iso_dt.clone(),
                        account.to_string(),
                        "".to_string(),
                        amount.to_string(),
                        k.clone(),
                        memo_str.clone(),
                    ]).map_err(|e| Client(anyhow!("Can't write CSV record")))?;
                }
            }
            many_modules::events::EventInfo::Send { from, to, symbol, memo, amount } => {
                if symbol != mfx {
                    continue;
                }

                let m = memo.unwrap_or(Memo::try_from("")?);
                let a: Vec<String> = m.iter_str().map(|s| s.to_string()).collect();
                let memo_str = if a.is_empty() {
                    "".to_string()
                }
                else {
                    format!("\"{}\"", a.join(" "))
                };

                wtr.write_record(&[
                    iso_dt,
                    from.to_string(),
                    to.to_string(),
                    amount.to_string(),
                    k.clone(),
                    memo_str,
                ]).map_err(|e| Client(anyhow!("Can't write CSV record")))?;
            }
            _ => {}
        }
    }

    Ok(())
}

fn main() -> Result<(), anyhow::Error> {
    let Opts {
        common_flags,
        servers,
    } = Opts::parse();

    common_flags.init_logging().unwrap();

    let mfx = many_identity::Address::from_str("mqbh742x4s356ddaryrxaowt4wxtlocekzpufodvowrirfrqaaaaa3l").expect("Can't parse MFX address");
    let clients = servers
        .iter()
        .map(|server| {
            ManyClient::new(server, Address::anonymous(), AnonymousIdentity)
                .map_err(|e| Client(anyhow!("Failed to create client: {}", e)))
        })
        .collect::<Result<Vec<_>, _>>().map_err(|e| anyhow!("Failed to create clients: {}", e.to_string()))?;

    let mut all_events = vec![];
    for (i, (s, c)) in servers.into_iter().zip(clients.into_iter()).enumerate() {
        println!("Processing server: {}", s);
        let events = load_or_fetch_events(i, c).map_err(|e| anyhow!("Failed to fetch events: {}", e))?;
        all_events.extend(events);
    }

    println!("Total events loaded: {}", all_events.len());

    parse_balances(&all_events, mfx).map_err(|e| anyhow!("Failed to parse events: {}", e))?;
    parse_transactions(all_events, mfx).map_err(|e| anyhow!("Failed to parse transactions: {}", e))?;

    Ok(())
}