//! VRP change history: one JSON line per applied update in
//! `<data_dir>/vrp-history.jsonl`, rotated to `.1` at a size limit.

use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::prefix::Prefix;
use crate::vrp::Vrp;

/// Customer AS -> providers.
pub type Aspas = std::collections::BTreeMap<u32, Vec<u32>>;

/// Longest history line read back; longer lines are skipped.
const MAX_LINE: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    /// RFC 3339.
    pub time: String,
    /// `baseline` (first set after start: not itemised) or `change`.
    pub kind: String,
    pub serial: Option<u32>,
    pub total: usize,
    pub added_count: usize,
    pub removed_count: usize,
    pub added: Vec<Vrp>,
    pub removed: Vec<Vrp>,
    /// Customer ASes whose ASPA record changed.
    #[serde(default)]
    pub aspa_changed: Vec<u32>,
    /// True when `added` / `removed` were cut at the per-event limit.
    pub truncated: bool,
}

/// Sorted-merge difference of two sorted, de-duplicated slices.
pub fn diff(old: &[Vrp], new: &[Vrp]) -> (Vec<Vrp>, Vec<Vrp>) {
    let (mut added, mut removed) = (Vec::new(), Vec::new());
    let (mut i, mut j) = (0, 0);
    while i < old.len() || j < new.len() {
        match (old.get(i), new.get(j)) {
            (Some(a), Some(b)) if a == b => {
                i += 1;
                j += 1;
            }
            (Some(a), Some(b)) if a < b => {
                removed.push(*a);
                i += 1;
            }
            (Some(_), Some(b)) => {
                added.push(*b);
                j += 1;
            }
            (Some(a), None) => {
                removed.push(*a);
                i += 1;
            }
            (None, Some(b)) => {
                added.push(*b);
                j += 1;
            }
            (None, None) => break,
        }
    }
    (added, removed)
}

#[derive(Debug, Default, Clone)]
pub struct Query {
    /// Matches VRPs whose prefix overlaps this prefix (either covers the other).
    pub prefix: Option<Prefix>,
    pub asn: Option<u32>,
    /// RFC 3339 lower bound (inclusive).
    pub since: Option<chrono::DateTime<chrono::Utc>>,
    pub limit: usize,
}

impl Query {
    fn matches(&self, v: &Vrp) -> bool {
        self.prefix
            .is_none_or(|p| p.covers(&v.prefix) || v.prefix.covers(&p))
            && self.asn.is_none_or(|a| a == v.asn)
    }

    fn filtered(&self, mut e: Event) -> Option<Event> {
        if let Some(since) = self.since {
            let t = chrono::DateTime::parse_from_rfc3339(&e.time).ok()?;
            if t < since {
                return None;
            }
        }
        if self.prefix.is_none() && self.asn.is_none() {
            return Some(e);
        }
        e.added.retain(|v| self.matches(v));
        e.removed.retain(|v| self.matches(v));
        e.aspa_changed
            .retain(|a| self.prefix.is_none() && Some(*a) == self.asn);
        (!e.added.is_empty() || !e.removed.is_empty() || !e.aspa_changed.is_empty()).then_some(e)
    }
}

pub struct History {
    path: PathBuf,
    max_bytes: u64,
    max_listed: usize,
    lock: Mutex<()>,
}

impl History {
    pub fn new(path: PathBuf, max_bytes: u64, max_listed: usize) -> Self {
        History {
            path,
            max_bytes,
            max_listed,
            lock: Mutex::new(()),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn rotated(&self) -> PathBuf {
        let mut p = self.path.clone().into_os_string();
        p.push(".1");
        PathBuf::from(p)
    }

    /// Builds the event for an update; `None` when nothing changed.
    pub fn event(
        &self,
        old: Option<(&[Vrp], &Aspas)>,
        new: &[Vrp],
        new_aspas: &Aspas,
        serial: Option<u32>,
    ) -> Option<Event> {
        let time = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let Some((old, old_aspas)) = old else {
            return Some(Event {
                time,
                kind: "baseline".into(),
                serial,
                total: new.len(),
                added_count: 0,
                removed_count: 0,
                added: vec![],
                removed: vec![],
                aspa_changed: vec![],
                truncated: false,
            });
        };
        let (mut added, mut removed) = diff(old, new);
        let aspa_changed: Vec<u32> = old_aspas
            .keys()
            .chain(new_aspas.keys())
            .copied()
            .collect::<std::collections::BTreeSet<u32>>()
            .into_iter()
            .filter(|k| old_aspas.get(k) != new_aspas.get(k))
            .collect();
        if added.is_empty() && removed.is_empty() && aspa_changed.is_empty() {
            return None;
        }
        let (added_count, removed_count) = (added.len(), removed.len());
        let truncated = added_count > self.max_listed || removed_count > self.max_listed;
        added.truncate(self.max_listed);
        removed.truncate(self.max_listed);
        Some(Event {
            time,
            kind: "change".into(),
            serial,
            total: new.len(),
            added_count,
            removed_count,
            added,
            removed,
            aspa_changed,
            truncated,
        })
    }

    pub fn append(&self, e: &Event) -> std::io::Result<()> {
        let _g = self
            .lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        if std::fs::metadata(&self.path).is_ok_and(|m| m.len() >= self.max_bytes) {
            std::fs::rename(&self.path, self.rotated())?;
        }
        let mut line = serde_json::to_vec(e).map_err(std::io::Error::other)?;
        line.push(b'\n');
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        f.write_all(&line)?;
        f.flush()
    }

    /// Newest-first events matching `q` (rotated file included).
    pub fn query(&self, q: &Query) -> std::io::Result<Vec<Event>> {
        let _g = self
            .lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut out = Vec::new();
        for path in [self.rotated(), self.path.clone()] {
            let f = match std::fs::File::open(&path) {
                Ok(f) => f,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e),
            };
            let mut r = BufReader::new(f);
            let mut buf = Vec::new();
            loop {
                buf.clear();
                let n = (&mut r)
                    .take(MAX_LINE as u64 + 1)
                    .read_until(b'\n', &mut buf)?;
                if n == 0 {
                    break;
                }
                if n > MAX_LINE {
                    // Skip the rest of an oversized line.
                    let mut sink = Vec::new();
                    r.read_until(b'\n', &mut sink)?;
                    continue;
                }
                if let Ok(e) = serde_json::from_slice::<Event>(&buf) {
                    if let Some(e) = q.filtered(e) {
                        out.push(e);
                    }
                }
            }
        }
        out.reverse();
        out.truncate(q.limit.max(1));
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn vrp(p: &str, max: u8, asn: u32) -> Vrp {
        Vrp::new(p.parse().unwrap(), max, asn).unwrap()
    }

    #[test]
    fn diff_sorted() {
        let a = [vrp("192.0.2.0/24", 24, 1), vrp("198.51.100.0/24", 24, 2)];
        let b = [vrp("192.0.2.0/24", 24, 1), vrp("203.0.113.0/24", 24, 3)];
        let (add, rem) = diff(&a, &b);
        assert_eq!(add, vec![vrp("203.0.113.0/24", 24, 3)]);
        assert_eq!(rem, vec![vrp("198.51.100.0/24", 24, 2)]);
        assert_eq!(diff(&a, &a), (vec![], vec![]));
        assert_eq!(diff(&[], &a).0.len(), 2);
    }

    #[test]
    fn append_query_rotate() {
        let dir = std::env::temp_dir().join(format!("notary-hist-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let h = History::new(dir.join("vrp-history.jsonl"), 300, 1);
        let none = BTreeMap::new();
        let a = vec![vrp("192.0.2.0/24", 24, 64500)];
        let b = vec![
            vrp("192.0.2.0/24", 24, 64500),
            vrp("198.51.100.0/24", 24, 64501),
        ];
        let c = vec![vrp("203.0.113.0/24", 24, 64502)];
        let base = h.event(None, &a, &none, Some(1)).unwrap();
        assert_eq!(base.kind, "baseline");
        h.append(&base).unwrap();
        assert!(h.event(Some((&a, &none)), &a, &none, Some(1)).is_none());
        h.append(&h.event(Some((&a, &none)), &b, &none, Some(2)).unwrap())
            .unwrap();
        let e = h.event(Some((&b, &none)), &c, &none, Some(3)).unwrap();
        assert!(e.truncated);
        assert_eq!((e.added_count, e.removed_count, e.removed.len()), (1, 2, 1));
        h.append(&e).unwrap();
        // Rotation happened at 300 bytes; both files are read.
        assert!(h.rotated().exists());
        let all = h
            .query(&Query {
                limit: 10,
                ..Query::default()
            })
            .unwrap();
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].serial, Some(3));
        let q = Query {
            asn: Some(64501),
            limit: 10,
            ..Query::default()
        };
        let r = h.query(&q).unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].added, vec![vrp("198.51.100.0/24", 24, 64501)]);
        let q = Query {
            prefix: Some("203.0.113.128/25".parse().unwrap()),
            limit: 10,
            ..Query::default()
        };
        assert_eq!(h.query(&q).unwrap().len(), 1);
        let q = Query {
            since: Some(chrono::Utc::now() + chrono::Duration::hours(1)),
            limit: 10,
            ..Query::default()
        };
        assert!(h.query(&q).unwrap().is_empty());
        // ASPA changes are recorded.
        let mut asp = BTreeMap::new();
        asp.insert(64500u32, vec![64510u32]);
        let e = h.event(Some((&c, &none)), &c, &asp, None).unwrap();
        assert_eq!(e.aspa_changed, vec![64500]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
