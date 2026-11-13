//! One-shot CLI commands.

use std::future::Future;
use std::io::{BufRead, Read};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{bail, Context};
use serde::Serialize;

use crate::aspa::{self, AspaState, Direction};
use crate::audit;
use crate::config::Config;
use crate::history::{self, History};
use crate::irr::{self, IrrSource};
use crate::prefix::{parse_asn, Prefix};
use crate::rtr::transport::{RtrTarget, TransportConfig};
use crate::slurm::Slurm;
use crate::sources::{self, PrefixSource};
use crate::validator::{self, explain_vrp, validate, Validation, Validity};
use crate::vrp::{self, VrpData, VrpTable};
use crate::{bench, http, rtr, PrefixArgs, SourceArgs};

/// Longest accepted line in bulk input.
const MAX_LINE: u64 = 1024;

pub fn block_on<F: Future<Output = anyhow::Result<ExitCode>>>(f: F) -> anyhow::Result<ExitCode> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting Tokio runtime")?
        .block_on(f)
}

/// Loads a source spec: rtr:// tcp:// tls:// ssh:// is an RTR cache,
/// anything else a JSON export path or URL.
async fn load_spec(
    spec: &str,
    transport: &TransportConfig,
    rtr_version: u8,
) -> anyhow::Result<(VrpData, String)> {
    if ["rtr://", "tcp://", "tls://", "ssh://"]
        .iter()
        .any(|s| spec.starts_with(s))
    {
        let target = RtrTarget::new(spec, transport.clone(), rtr_version)?;
        let snap = rtr::client::fetch(&target).await?;
        let label = format!("{target} (v{}, serial {})", snap.version, snap.serial);
        Ok((snap.data(), label))
    } else {
        Ok((
            vrp::load_json_data(spec, &http::client()?).await?,
            spec.to_string(),
        ))
    }
}

/// Loads VRPs per `--vrps` / `--rtr`, applies SLURM and refuses empty sets.
async fn load_source(
    s: &SourceArgs,
    default_version: u8,
) -> anyhow::Result<Option<(VrpTable, String)>> {
    let (mut data, label) = match (&s.vrps, &s.rtr) {
        (Some(src), None) => load_spec(src, &s.transport, 0).await?,
        (None, Some(addr)) => {
            let version = s.rtr_version.unwrap_or(default_version);
            let target = RtrTarget::new(addr, s.transport.clone(), version)?;
            let snap = rtr::client::fetch(&target).await?;
            let label = format!("{target} (v{}, serial {})", snap.version, snap.serial);
            (snap.data(), label)
        }
        (None, None) => return Ok(None),
        _ => bail!("give only one of --vrps or --rtr"),
    };
    let label = match Slurm::load(&s.slurm)? {
        Some(sl) => {
            let (f, a) = sl.apply(&mut data);
            format!("{label} + SLURM (-{f} +{a})")
        }
        None => label,
    };
    if data.vrps.is_empty() {
        bail!("VRP source {label} is empty; refusing to validate against no data");
    }
    Ok(Some((VrpTable::build(data), label)))
}

async fn require_source(s: &SourceArgs, default_version: u8) -> anyhow::Result<(VrpTable, String)> {
    load_source(s, default_version)
        .await?
        .ok_or_else(|| anyhow::anyhow!("give one of --vrps or --rtr"))
}

fn exit_for(v: Validity) -> ExitCode {
    match v {
        Validity::Valid => ExitCode::SUCCESS,
        Validity::Invalid(_) => ExitCode::from(2),
        Validity::NotFound => ExitCode::from(3),
    }
}

fn expiry_note(table: &VrpTable, r: &Validation) -> Option<String> {
    let exp = r
        .covering
        .iter()
        .filter(|c| validator::matches(c, &r.prefix, r.origin))
        .map(|c| table.expires(c))
        .max_by_key(|e| e.unwrap_or(i64::MAX))??;
    let t = chrono::DateTime::from_timestamp(exp, 0)?;
    let days = (exp - chrono::Utc::now().timestamp()) / 86_400;
    Some(format!(
        "Authorising ROA(s) expire {} ({days} days)",
        t.to_rfc3339()
    ))
}

pub async fn check(
    prefix: &str,
    asn: &str,
    s: &SourceArgs,
    json: bool,
) -> anyhow::Result<ExitCode> {
    let prefix: Prefix = prefix
        .parse()
        .with_context(|| format!("invalid prefix {prefix:?}"))?;
    let asn = parse_asn(asn).with_context(|| format!("invalid AS number {asn:?}"))?;
    let (table, source) = require_source(s, 1).await?;
    let result = validate(&table, &prefix, asn);
    if json {
        let mut v = serde_json::to_value(&result)?;
        if let Some(e) = result
            .covering
            .iter()
            .filter(|c| validator::matches(c, &prefix, asn))
            .filter_map(|c| table.expires(c))
            .max()
        {
            v["expires"] = e.into();
        }
        println!("{}", serde_json::to_string_pretty(&v)?);
    } else {
        print_human(&result, &source, table.len());
        if let Some(n) = expiry_note(&table, &result) {
            println!("{n}");
        }
    }
    Ok(exit_for(result.validity))
}

fn print_human(r: &Validation, source: &str, total: usize) {
    println!("Route   {} origin AS{}", r.prefix, r.origin);
    println!("Source  {source} ({total} VRPs)");
    println!("Result  {}", r.validity);
    if r.covering.is_empty() {
        println!();
        println!("No VRP covers this prefix, so RPKI has no opinion on it.");
        return;
    }
    println!();
    println!("Covering VRPs ({}):", r.covering.len());
    for v in &r.covering {
        let max = format!("max /{}", v.max_length);
        println!(
            "  {:<22} {:<8} AS{:<10} {}",
            v.prefix.to_string(),
            max,
            v.asn,
            explain_vrp(v, &r.prefix, r.origin)
        );
    }
    println!();
    let why = match r.validity {
        Validity::Valid => "At least one covering VRP authorises this origin at this prefix length.",
        Validity::Invalid(validator::InvalidReason::WrongOrigin) => {
            "No covering VRP lists this origin AS. Networks that drop RPKI-invalid routes will reject it."
        }
        Validity::Invalid(validator::InvalidReason::MaxLengthExceeded) => {
            "The origin is authorised, but the route is more specific than every matching maxLength."
        }
        Validity::NotFound => "",
    };
    println!("{why}");
}

/// Parses one bulk line: `prefix asn`, `prefix,asn` or `prefix AS64500`.
pub fn parse_route_line(line: &str) -> anyhow::Result<Option<(Prefix, u32)>> {
    let line = line.split('#').next().unwrap_or("").trim();
    if line.is_empty() {
        return Ok(None);
    }
    let mut it = line
        .split(|c: char| c.is_whitespace() || c == ',' || c == ';')
        .filter(|t| !t.is_empty());
    let (Some(p), Some(a), None) = (it.next(), it.next(), it.next()) else {
        bail!("expected \"prefix asn\"");
    };
    let prefix: Prefix = p.parse().with_context(|| format!("prefix {p:?}"))?;
    let asn = parse_asn(a).with_context(|| format!("AS number {a:?}"))?;
    Ok(Some((prefix, asn)))
}

pub async fn check_bulk(file: &str, s: &SourceArgs, json: bool) -> anyhow::Result<ExitCode> {
    let (table, source) = require_source(s, 1).await?;
    let reader: Box<dyn BufRead> = if file == "-" {
        Box::new(std::io::BufReader::new(std::io::stdin()))
    } else {
        Box::new(std::io::BufReader::new(
            std::fs::File::open(file).with_context(|| format!("opening {file}"))?,
        ))
    };
    let mut reader = reader;
    let (mut valid, mut invalid, mut not_found, mut errors) = (0u64, 0u64, 0u64, 0u64);
    let mut buf = Vec::new();
    let mut lineno = 0u64;
    loop {
        buf.clear();
        let n = (&mut reader)
            .take(MAX_LINE + 1)
            .read_until(b'\n', &mut buf)?;
        if n == 0 {
            break;
        }
        lineno += 1;
        if n as u64 > MAX_LINE && !buf.ends_with(b"\n") {
            eprintln!("line {lineno}: longer than {MAX_LINE} bytes, skipped");
            errors += 1;
            let mut rest = Vec::new();
            reader.read_until(b'\n', &mut rest)?;
            continue;
        }
        let line = String::from_utf8_lossy(&buf);
        match parse_route_line(&line) {
            Ok(None) => {}
            Ok(Some((prefix, asn))) => {
                let r = validate(&table, &prefix, asn);
                match r.validity {
                    Validity::Valid => valid += 1,
                    Validity::Invalid(_) => invalid += 1,
                    Validity::NotFound => not_found += 1,
                }
                if json {
                    println!("{}", serde_json::to_string(&r)?);
                } else {
                    println!("{:<22} AS{:<10} {}", prefix.to_string(), asn, r.validity);
                }
            }
            Err(e) => {
                errors += 1;
                eprintln!("line {lineno}: {e:#}");
            }
        }
    }
    eprintln!(
        "{} routes against {source} ({} VRPs): {valid} valid, {invalid} invalid, {not_found} not found, {errors} bad lines",
        valid + invalid + not_found,
        table.len()
    );
    Ok(if errors > 0 {
        ExitCode::FAILURE
    } else if invalid > 0 {
        ExitCode::from(2)
    } else if not_found > 0 {
        ExitCode::from(3)
    } else {
        ExitCode::SUCCESS
    })
}

async fn announced(asn: u32, p: &PrefixArgs) -> anyhow::Result<(Vec<Prefix>, PrefixSource)> {
    let src = PrefixSource::from_cli(&p.prefixes_from, p.user_agent.as_deref())?;
    let max = p.max_prefixes.clamp(1, 1_000_000);
    let mut map = sources::fetch(&http::client()?, &src, &[asn], max).await?;
    let (list, truncated) = map.remove(&asn).unwrap_or_default();
    if truncated {
        eprintln!("warning: prefix list truncated at {max}; raise --max-prefixes");
    }
    Ok((list, src))
}

pub async fn suggest(
    asn: &str,
    p: &PrefixArgs,
    s: &SourceArgs,
    json: bool,
) -> anyhow::Result<ExitCode> {
    let asn = parse_asn(asn).with_context(|| format!("invalid AS number {asn:?}"))?;
    let table = load_source(s, 1).await?;
    let (prefixes, src) = announced(asn, p).await?;
    let list = audit::suggest(table.as_ref().map(|t| &t.0), asn, &prefixes);
    if json {
        println!("{}", serde_json::to_string_pretty(&list)?);
        return Ok(ExitCode::SUCCESS);
    }
    println!(
        "AS{asn}: {} announced prefixes (source {src})",
        prefixes.len()
    );
    if let Some((t, label)) = &table {
        println!("Compared with {label} ({} VRPs)", t.len());
    }
    println!();
    println!("  {:<44} {:<9} {:<10} STATUS", "PREFIX", "MAXLEN", "ASN");
    for x in &list {
        println!(
            "  {:<44} {:<9} AS{:<8} {}",
            x.prefix.to_string(),
            x.max_length,
            x.asn,
            x.status
        );
    }
    let todo = list.iter().filter(|x| x.status != "covered").count();
    println!();
    println!("{todo} ROA(s) to create; each uses maxLength = prefix length (RFC 9319).");
    Ok(ExitCode::SUCCESS)
}

pub async fn audit(
    asn: &str,
    p: &PrefixArgs,
    s: &SourceArgs,
    json: bool,
) -> anyhow::Result<ExitCode> {
    let asn = parse_asn(asn).with_context(|| format!("invalid AS number {asn:?}"))?;
    let (table, label) = require_source(s, 1).await?;
    let (prefixes, src) = announced(asn, p).await?;
    let loose = audit::audit_max_length(&table, asn, &prefixes);
    if json {
        println!("{}", serde_json::to_string_pretty(&loose)?);
    } else {
        let own = table.vrps().iter().filter(|v| v.asn == asn).count();
        println!(
            "AS{asn}: {own} VRPs in {label}, {} announced prefixes (source {src})",
            prefixes.len()
        );
        if loose.is_empty() {
            println!("No loose maxLength: every VRP authorises only announced prefixes.");
        }
        for l in &loose {
            println!();
            println!(
                "LOOSE  {} max /{}  authorises {} prefixes, {} announced, {} unannounced",
                l.vrp.prefix,
                l.vrp.max_length,
                l.authorised,
                l.announced.len(),
                l.unannounced
            );
            if l.replace_with.is_empty() {
                println!("       nothing announced inside it: consider removing the ROA");
            } else {
                for r in &l.replace_with {
                    println!("       replace with ROA {r} max /{} AS{asn}", r.len());
                }
            }
        }
    }
    Ok(if loose.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    })
}

pub async fn irr(asn: &str, irr_src: &str, s: &SourceArgs, json: bool) -> anyhow::Result<ExitCode> {
    let asn = parse_asn(asn).with_context(|| format!("invalid AS number {asn:?}"))?;
    let src = IrrSource::parse(irr_src)?;
    let (table, label) = require_source(s, 1).await?;
    let objects = irr::fetch(&http::client()?, &src, asn).await?;
    let findings = irr::compare(&table, &objects, asn);
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "asn": asn,
                "route_objects": objects,
                "findings": findings,
            }))?
        );
    } else {
        println!(
            "AS{asn}: {} route/route6 objects from {irr_src}, VRPs from {label}",
            objects.len()
        );
        if findings.is_empty() {
            println!("IRR and RPKI agree.");
        }
        for f in &findings {
            println!(
                "  {:<44} {:<28} {}",
                f.prefix.to_string(),
                f.issue,
                f.detail
            );
        }
    }
    Ok(if findings.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    })
}

pub async fn aspa(
    path: &str,
    direction: Direction,
    s: &SourceArgs,
    json: bool,
) -> anyhow::Result<ExitCode> {
    let path = aspa::parse_path(path)?;
    let (table, label) = require_source(s, 2).await?;
    let r = aspa::verify(&table, &path, direction);
    if json {
        println!("{}", serde_json::to_string_pretty(&r)?);
    } else {
        let p: Vec<String> = r.path.iter().map(|a| format!("AS{a}")).collect();
        println!("Path    {} ({:?})", p.join(" "), direction);
        println!("Source  {label} ({} ASPA records)", table.aspa_count());
        println!("Result  {}", r.state);
        println!();
        for (c, pr, h) in &r.hops {
            println!("  AS{c:<10} -> AS{pr:<10} {h:?}");
        }
    }
    Ok(match r.state {
        AspaState::Valid => ExitCode::SUCCESS,
        AspaState::Invalid => ExitCode::from(2),
        AspaState::Unknown => ExitCode::from(3),
    })
}

#[derive(Serialize)]
struct DiffReport<'a> {
    a: &'a str,
    b: &'a str,
    a_count: usize,
    b_count: usize,
    only_in_a: usize,
    only_in_b: usize,
    aspa_differs: Vec<u32>,
    only_in_a_sample: &'a [crate::vrp::Vrp],
    only_in_b_sample: &'a [crate::vrp::Vrp],
}

pub async fn diff(
    a: &str,
    b: &str,
    rtr_version: u8,
    transport: &TransportConfig,
    show: usize,
    json: bool,
) -> anyhow::Result<ExitCode> {
    let (ra, rb) = tokio::join!(
        load_spec(a, transport, rtr_version),
        load_spec(b, transport, rtr_version)
    );
    let ((da, la), (db, lb)) = (ra.context(a.to_string())?, rb.context(b.to_string())?);
    let (ta, tb) = (VrpTable::build(da), VrpTable::build(db));
    // history::diff(old, new): "added" = only in B, "removed" = only in A.
    let (only_b, only_a) = history::diff(ta.vrps(), tb.vrps());
    let aspa_differs: Vec<u32> = ta
        .data()
        .aspas
        .keys()
        .chain(tb.data().aspas.keys())
        .copied()
        .collect::<std::collections::BTreeSet<u32>>()
        .into_iter()
        .filter(|k| ta.aspa(*k) != tb.aspa(*k))
        .collect();
    let same = only_a.is_empty() && only_b.is_empty() && aspa_differs.is_empty();
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&DiffReport {
                a: &la,
                b: &lb,
                a_count: ta.len(),
                b_count: tb.len(),
                only_in_a: only_a.len(),
                only_in_b: only_b.len(),
                aspa_differs,
                only_in_a_sample: &only_a[..only_a.len().min(show)],
                only_in_b_sample: &only_b[..only_b.len().min(show)],
            })?
        );
    } else {
        println!("A  {la}: {} VRPs, {} ASPA", ta.len(), ta.aspa_count());
        println!("B  {lb}: {} VRPs, {} ASPA", tb.len(), tb.aspa_count());
        println!(
            "Only in A: {}   Only in B: {}   ASPA records differing: {}",
            only_a.len(),
            only_b.len(),
            aspa_differs.len()
        );
        for (tag, list) in [("A", &only_a), ("B", &only_b)] {
            for v in list.iter().take(show) {
                println!(
                    "  {tag}  {:<44} max /{:<3} AS{}",
                    v.prefix.to_string(),
                    v.max_length,
                    v.asn
                );
            }
            if list.len() > show {
                println!("  {tag}  ... {} more", list.len() - show);
            }
        }
        if same {
            println!("The sources agree.");
        }
    }
    Ok(if same {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    })
}

/// Data directory: explicit flag, else from the config file if present,
/// else the platform default.
fn data_dir(config: &Path, explicit: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    if let Some(d) = explicit {
        return Ok(d);
    }
    if config.exists() {
        return Ok(Config::load(config)?.data_dir());
    }
    Ok(llcforge_beacon::default_data_dir(crate::state::TOOL))
}

pub fn silence_path(config: &Path) -> anyhow::Result<PathBuf> {
    if config.exists() {
        let c = Config::load(config)?;
        return Ok(c.silences.path_or(&c.data_dir()));
    }
    Ok(llcforge_beacon::default_data_dir(crate::state::TOOL).join("silences.json"))
}

pub fn history(
    config: &Path,
    prefix: Option<String>,
    asn: Option<String>,
    since: Option<String>,
    limit: usize,
    dir: Option<PathBuf>,
    json: bool,
) -> anyhow::Result<ExitCode> {
    let dir = data_dir(config, dir)?;
    let q = history::Query {
        prefix: prefix.map(|p| p.parse()).transpose().context("--prefix")?,
        asn: asn.map(|a| parse_asn(&a)).transpose().context("--asn")?,
        since: since
            .map(|s| {
                chrono::DateTime::parse_from_rfc3339(&s).map(|t| t.with_timezone(&chrono::Utc))
            })
            .transpose()
            .context("--since expects RFC 3339")?,
        limit: limit.clamp(1, 100_000),
    };
    let h = History::new(dir.join("vrp-history.jsonl"), u64::MAX, usize::MAX);
    let events = h.query(&q)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&events)?);
        return Ok(ExitCode::SUCCESS);
    }
    if events.is_empty() {
        println!("No matching VRP changes in {}", h.path().display());
    }
    for e in &events {
        println!(
            "{}  {:<8} serial {:<10} total {:<8} +{} -{}{}",
            e.time,
            e.kind,
            e.serial.map_or_else(|| "-".into(), |s| s.to_string()),
            e.total,
            e.added_count,
            e.removed_count,
            if e.truncated { " (list truncated)" } else { "" }
        );
        for v in &e.added {
            println!(
                "    + {:<44} max /{:<3} AS{}",
                v.prefix.to_string(),
                v.max_length,
                v.asn
            );
        }
        for v in &e.removed {
            println!(
                "    - {:<44} max /{:<3} AS{}",
                v.prefix.to_string(),
                v.max_length,
                v.asn
            );
        }
        for a in &e.aspa_changed {
            println!("    ~ ASPA of AS{a}");
        }
    }
    Ok(ExitCode::SUCCESS)
}

pub async fn bench(
    vrps: Option<String>,
    v4: usize,
    v6: usize,
    lookups: usize,
    json: bool,
) -> anyhow::Result<ExitCode> {
    let data = match vrps {
        Some(src) => Some(vrp::load_json_data(&src, &http::client()?).await?),
        None => None,
    };
    if data.as_ref().is_some_and(|d| d.vrps.is_empty()) {
        bail!("the VRP source is empty");
    }
    if v4 + v6 == 0 && data.is_none() {
        bail!("nothing to benchmark: --v4 and --v6 are both 0");
    }
    let lookups = lookups.clamp(1, 100_000_000);
    let r = tokio::task::spawn_blocking(move || bench::run(data, v4, v6, lookups)).await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&r)?);
    } else {
        bench::print(&r);
    }
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bulk_lines() {
        let ok = |s: &str| parse_route_line(s).unwrap().unwrap();
        assert_eq!(ok("192.0.2.0/24 AS64500").1, 64500);
        assert_eq!(ok("  192.0.2.0/24,64500 # comment").1, 64500);
        assert_eq!(ok("2001:db8::/32\t64501").0.to_string(), "2001:db8::/32");
        assert!(parse_route_line("# only a comment").unwrap().is_none());
        assert!(parse_route_line("   ").unwrap().is_none());
        assert!(parse_route_line("192.0.2.0/24").is_err());
        assert!(parse_route_line("192.0.2.0/24 1 2").is_err());
        assert!(parse_route_line("192.0.2.1/24 1").is_err());
    }

    #[tokio::test]
    async fn source_loading_and_slurm() {
        let fixture = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/vrps.json");
        let s = SourceArgs {
            vrps: Some(fixture.into()),
            ..Default::default()
        };
        let (t, label) = require_source(&s, 1).await.unwrap();
        assert!(!t.is_empty());
        assert_eq!(label, fixture);
        assert!(require_source(&SourceArgs::default(), 1).await.is_err());
        let s = SourceArgs {
            vrps: Some(fixture.into()),
            slurm: vec![concat!(env!("CARGO_MANIFEST_DIR"), "/examples/slurm.json").into()],
            ..Default::default()
        };
        let (_, label) = require_source(&s, 1).await.unwrap();
        assert!(label.contains("SLURM"), "{label}");
    }
}
