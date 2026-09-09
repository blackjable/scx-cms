// SPDX-License-Identifier: GPL-2.0
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::collections::HashSet;
use std::fs;
use std::path::Path;

const MECHANISM_DIR: &str = "src/bpf/mechanisms";

struct Mechanism {
    id: u32,
    name: String,
}

/// Parse the rows of CMS_MECHANISM_LIST out of mechanisms/index.h.
///
/// That list is the single place a mechanism is registered; the kernel-side
/// dispatch is generated from it by the C preprocessor, and the
/// `--mechanism` command-line values are generated from it here. Keeping
/// one source means the two cannot disagree.
fn parse_index(index: &str) -> Result<Vec<Mechanism>, String> {
    let body = index
        .split_once("#define CMS_MECHANISM_LIST(X)")
        .ok_or_else(|| {
            format!("{MECHANISM_DIR}/index.h: no `#define CMS_MECHANISM_LIST(X)` found")
        })?
        .1;

    let mut out = Vec::new();

    for raw in body.lines() {
        let line = raw.trim().trim_end_matches('\\').trim();
        if line.is_empty() || line.starts_with("/*") || line.starts_with('*') {
            continue;
        }
        // Rows look like: X(1,  penalty,  cms_mech_penalty)
        let Some(args) = line
            .strip_prefix("X(")
            .and_then(|rest| rest.strip_suffix(')'))
        else {
            break; // end of the macro body
        };

        let fields: Vec<&str> = args.split(',').map(|f| f.trim()).collect();
        if fields.len() != 3 {
            return Err(format!(
                "{MECHANISM_DIR}/index.h: malformed row `{line}`\n  \
                 expected: X(<id>, <name>, <function>)"
            ));
        }

        let id: u32 = fields[0].parse().map_err(|_| {
            format!("{MECHANISM_DIR}/index.h: row `{line}` has non-numeric id `{}`", fields[0])
        })?;

        out.push(Mechanism {
            id,
            name: fields[1].to_string(),
        });
    }

    if out.is_empty() {
        return Err(format!("{MECHANISM_DIR}/index.h: CMS_MECHANISM_LIST is empty"));
    }

    Ok(out)
}

/// Fail the build on the mistakes the compiler cannot catch.
///
/// The important one is an unlisted file: it compiles perfectly happily,
/// because nothing references it, and the only symptom is `--mechanism
/// yourthing` reporting an invalid value at run time. Checks that the
/// compiler *does* handle -- such as whether a listed function actually
/// exists -- are deliberately not duplicated here.
fn validate(mechanisms: &[Mechanism], index: &str, dir: &Path) -> Result<(), String> {
    let listed: HashSet<&str> = mechanisms.iter().map(|m| m.name.as_str()).collect();

    if listed.len() != mechanisms.len() {
        return Err(format!(
            "{MECHANISM_DIR}/index.h: duplicate mechanism name in CMS_MECHANISM_LIST"
        ));
    }

    let ids: HashSet<u32> = mechanisms.iter().map(|m| m.id).collect();
    if ids.len() != mechanisms.len() {
        return Err(format!(
            "{MECHANISM_DIR}/index.h: duplicate mechanism id in CMS_MECHANISM_LIST"
        ));
    }

    for m in mechanisms {
        if !m.name.chars().all(|c| c.is_ascii_lowercase() || c == '_') {
            return Err(format!(
                "{MECHANISM_DIR}/index.h: `{}` is not usable as a --mechanism value\n  \
                 use lowercase letters and underscores only",
                m.name
            ));
        }

        let file = dir.join(format!("{}.bpf.c", m.name));
        if !file.exists() {
            return Err(format!(
                "{MECHANISM_DIR}/index.h lists `{}` but {}/{}.bpf.c does not exist\n  \
                 write the file, or remove the row from CMS_MECHANISM_LIST",
                m.name, MECHANISM_DIR, m.name
            ));
        }

        if !index.contains(&format!("#include \"{}.bpf.c\"", m.name)) {
            return Err(format!(
                "{MECHANISM_DIR}/index.h lists `{}` but never includes it\n  \
                 add: #include \"{}.bpf.c\"",
                m.name, m.name
            ));
        }
    }

    // The check that earns its keep: a file present but never registered.
    for entry in fs::read_dir(dir).map_err(|e| format!("cannot read {MECHANISM_DIR}: {e}"))? {
        let entry = entry.map_err(|e| format!("cannot read {MECHANISM_DIR}: {e}"))?;
        let path = entry.path();
        let Some(file_name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let Some(stem) = file_name.strip_suffix(".bpf.c") else {
            continue;
        };

        if !listed.contains(stem) {
            return Err(format!(
                "{MECHANISM_DIR}/{file_name} exists but is not listed in index.h\n  \
                 add `X(<next id>, {stem}, cms_mech_{stem})` to CMS_MECHANISM_LIST \
                 and `#include \"{file_name}\"`,\n  or delete the file if it is dead"
            ));
        }
    }

    Ok(())
}

/// Generate the `--mechanism` command-line type from the same list the
/// kernel-side dispatch is built from.
fn generate_rust(mechanisms: &[Mechanism]) -> String {
    let mut variants = String::new();
    let mut arms = String::new();

    for m in mechanisms {
        // penalty -> Penalty
        let mut chars = m.name.chars();
        let variant: String = match chars.next() {
            Some(first) => first.to_ascii_uppercase().to_string() + chars.as_str(),
            None => continue,
        };
        let variant = variant.replace('_', "");

        variants.push_str(&format!("    {variant},\n"));
        arms.push_str(&format!(
            "            Mechanism::{variant} => {},\n",
            m.id
        ));
    }

    format!(
        "// @generated from src/bpf/mechanisms/index.h -- do not edit.\n\
         //\n\
         // Add a mechanism by registering it in that file; this type follows.\n\
         #[derive(Clone, Copy, Debug, clap::ValueEnum)]\n\
         pub enum Mechanism {{\n{variants}}}\n\
         \n\
         impl Mechanism {{\n\
         \x20   pub fn as_bpf_const(self) -> u32 {{\n\
         \x20       match self {{\n{arms}\x20       }}\n\
         \x20   }}\n\
         }}\n"
    )
}

fn main() {
    let dir = Path::new(MECHANISM_DIR);
    let index_path = dir.join("index.h");

    println!("cargo:rerun-if-changed={}", index_path.display());
    println!("cargo:rerun-if-changed={MECHANISM_DIR}");

    let index = fs::read_to_string(&index_path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", index_path.display()));

    let mechanisms = parse_index(&index).unwrap_or_else(|e| panic!("{e}"));
    validate(&mechanisms, &index, dir).unwrap_or_else(|e| panic!("{e}"));

    let out = std::env::var("OUT_DIR").unwrap();
    fs::write(Path::new(&out).join("mechanisms.rs"), generate_rust(&mechanisms))
        .expect("cannot write generated mechanisms.rs");

    scx_cargo::BpfBuilder::new()
        .unwrap()
        .enable_intf("src/bpf/intf.h", "bpf_intf.rs")
        .enable_skel("src/bpf/main.bpf.c", "bpf")
        .build()
        .unwrap();
}
