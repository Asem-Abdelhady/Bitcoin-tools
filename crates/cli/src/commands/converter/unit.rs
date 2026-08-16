//! `converter unit` — one amount in satoshi, µBTC, mBTC and BTC.

use std::io::{self, Write};
use std::path::PathBuf;

use anyhow::{Context as _, Result};
use clap::ArgGroup;
use serde::{Deserialize, Serialize};

use bitcoin_tools_core::general::{Amount, Denomination};

use crate::input;
use crate::output::{Context, Fields, Output, yes_no};

/// What `converter unit` accepts.
///
/// The unit is the flag — `--bitcoin 1.5`, not `1.5 --denomination btc` — for
/// the reason [`base`](super::base) gives: `1` is a satoshi or a hundred
/// million of them, and an amount that arrives without its unit is not an
/// amount. Here there is no argument that carries one without the other.
///
/// The four units and `--input` are one required, non-multiple [`ArgGroup`],
/// so "exactly one of these five" is declared once rather than checked here.
#[derive(Debug, clap::Args)]
#[command(override_usage = "bitcoin-tools converter unit \
                            --satoshi|--microbitcoin|--millibitcoin|--bitcoin <AMOUNT>\n\
                          \x20      bitcoin-tools converter unit --input <FILE>")]
#[command(group = ArgGroup::new("source")
    .args(["satoshi", "microbitcoin", "millibitcoin", "bitcoin", "input"])
    .required(true))]
pub struct Args {
    /// An amount in satoshis, the indivisible base unit.
    #[arg(long, value_name = "AMOUNT", visible_aliases = ["sat", "sats"])]
    satoshi: Option<String>,

    /// An amount in µBTC, also called bits. 100 satoshis.
    #[arg(long, value_name = "AMOUNT", visible_aliases = ["ubtc", "bits"])]
    microbitcoin: Option<String>,

    /// An amount in mBTC. 100 000 satoshis.
    #[arg(long, value_name = "AMOUNT", visible_alias = "mbtc")]
    millibitcoin: Option<String>,

    /// An amount in BTC. 100 000 000 satoshis.
    #[arg(long, value_name = "AMOUNT", visible_alias = "btc")]
    bitcoin: Option<String>,

    /// Read the request from a JSON file, or `-` for stdin.
    ///
    /// The file holds an `amount` and a `denomination`. This is
    /// a superset of the HTTP API's request body: any body the API accepts
    /// works here, and `denomination` additionally takes the short spellings
    /// `sat`, `ubtc`, `bit`, `mbtc`, `btc` and the plurals, which the API
    /// refuses.
    #[arg(long, value_name = "FILE")]
    input: Option<PathBuf>,
}

impl Args {
    /// The request the flags describe, if a unit flag was the source.
    ///
    /// Each amount is written beside the unit it is in, so no ordering
    /// assumption can read an amount in the wrong one — which here would be
    /// wrong by a factor of a hundred million.
    fn given(self) -> Option<Request> {
        let (amount, denomination) = [
            (self.satoshi, Denomination::Satoshi),
            (self.microbitcoin, Denomination::MicroBitcoin),
            (self.millibitcoin, Denomination::MilliBitcoin),
            (self.bitcoin, Denomination::Bitcoin),
        ]
        .into_iter()
        .find_map(|(amount, denomination)| amount.map(|amount| (amount, denomination)))?;

        Some(Request {
            amount,
            denomination,
        })
    }
}

/// The resolved request, and the shape `--input` reads.
///
/// The wire shape keeps `amount` and `denomination` as the HTTP API spells
/// them even though the argument surface no longer does: a request file is a
/// thing scripts write and move between the two front ends.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Request {
    amount: String,
    #[serde(deserialize_with = "input::from_str")]
    denomination: Denomination,
}

/// One amount, in every unit.
///
/// Every value is a **string**, including the satoshi count, and for the same
/// reason the input is: an amount taken off the wire can be past 2^53, where a
/// JSON number stops being exact in most consumers. A *converter* would be the
/// last place a value should change on its way through.
///
/// Each of the four keys is the long form of the flag that would produce it,
/// and is a spelling `--input`'s `denomination` accepts. They are also exactly
/// the keys the HTTP API answers under, which is why they are not camelCased:
/// `microBitcoin` would be a second spelling of a value already named twice.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UnitOutput {
    /// Satoshis. Always whole — nothing divides one.
    satoshi: String,
    /// µBTC, also called bits. 100 satoshis.
    microbitcoin: String,
    /// mBTC. 100 000 satoshis.
    millibitcoin: String,
    /// BTC. 100 000 000 satoshis.
    bitcoin: String,
    /// Whether this is an amount Bitcoin can actually hold: at or below 21
    /// million BTC.
    ///
    /// Reported rather than enforced. The domain declines to cap it because a
    /// malformed transaction may declare any `u64` and a tool has to be able to
    /// show it, so the question gets answered instead of turned into a refusal.
    is_money_range: bool,
}

impl From<Amount> for UnitOutput {
    fn from(amount: Amount) -> Self {
        // Each field names the unit it renders, so no ordering assumption can
        // put an answer under the wrong key.
        UnitOutput {
            satoshi: amount.to_string_in(Denomination::Satoshi),
            microbitcoin: amount.to_string_in(Denomination::MicroBitcoin),
            millibitcoin: amount.to_string_in(Denomination::MilliBitcoin),
            bitcoin: amount.to_string_in(Denomination::Bitcoin),
            is_money_range: amount.is_money_range(),
        }
    }
}

impl Output for UnitOutput {
    fn render(&self, w: &mut dyn Write) -> io::Result<()> {
        Fields::new()
            .row("satoshi", &self.satoshi)
            .row("microbitcoin", &self.microbitcoin)
            .row("millibitcoin", &self.millibitcoin)
            .row("bitcoin", &self.bitcoin)
            .row("in money range", yes_no(self.is_money_range))
            .write(w)
    }
}

/// Parse the amount in the unit its flag named, render it in all four.
///
/// # Errors
///
/// If the request cannot be read, or the amount is not one: empty, negative, a
/// stray character, a second decimal point, a fraction finer than the unit
/// holds, or more satoshis than fit in a `u64`.
pub fn run(mut args: Args, ctx: Context) -> Result<()> {
    // Taken out rather than cloned: `given` consumes the rest.
    let source = args.input.take();
    let request: Request = input::resolve(source.as_deref(), || args.given())?;

    let amount = Amount::parse(&request.amount, request.denomination).with_context(|| {
        format!(
            "reading {} as {}",
            input::excerpt(&request.amount),
            request.denomination
        )
    })?;

    ctx.emit(&UnitOutput::from(amount))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each flag names the unit its amount is read in. A mismatched pair would
    /// be wrong by a factor of a hundred million and would look plausible.
    #[test]
    fn each_flag_reads_its_amount_in_its_own_unit() {
        let cases = [
            (Denomination::Satoshi, "150000000"),
            (Denomination::MicroBitcoin, "1500000"),
            (Denomination::MilliBitcoin, "1500"),
            (Denomination::Bitcoin, "1.5"),
        ];

        for (denomination, amount) in cases {
            let pick = |d: Denomination| (d == denomination).then(|| amount.to_owned());

            let args = Args {
                satoshi: pick(Denomination::Satoshi),
                microbitcoin: pick(Denomination::MicroBitcoin),
                millibitcoin: pick(Denomination::MilliBitcoin),
                bitcoin: pick(Denomination::Bitcoin),
                input: None,
            };

            let request = args.given().expect("a unit flag was given");

            assert_eq!(request.denomination, denomination);
            assert_eq!(
                Amount::parse(&request.amount, request.denomination)
                    .expect("parses")
                    .to_sat(),
                150_000_000,
                "{denomination} read the wrong amount"
            );
        }
    }

    /// Every unit the domain has is answered, and every key answers back.
    ///
    /// Two properties in one loop, and the second is the one worth having: a
    /// key of this output names the flag that produces it, and is a spelling
    /// `--input` accepts. Pinned against `Denomination::all` rather than
    /// restated, so a fifth unit fails here instead of being silently missing.
    #[test]
    fn every_denomination_is_answered_under_a_key_that_reads_back_as_itself() {
        let output = UnitOutput::from(Amount::from_sat(1));
        let json = serde_json::to_value(&output).unwrap();
        let object = json.as_object().unwrap();

        for denomination in Denomination::all() {
            let key = object
                .keys()
                .find(|key| key.parse::<Denomination>() == Ok(denomination))
                .unwrap_or_else(|| panic!("no key reads back as {denomination}: {json}"));

            assert!(object[key].is_string(), "{key} is not a string: {json}");
        }
    }

    #[test]
    fn a_typo_in_the_request_file_is_an_error() {
        assert!(serde_json::from_str::<Request>(r#"{"amount":"1","denom":"btc"}"#).is_err());
    }

    #[test]
    fn the_denomination_is_required_in_a_request_file_too() {
        assert!(serde_json::from_str::<Request>(r#"{"amount":"1"}"#).is_err());
    }
}
