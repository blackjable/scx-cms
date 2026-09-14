// SPDX-License-Identifier: GPL-2.0
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::collections::HashSet;
use std::fs;
use std::path::Path;

/// One pluggable axis of the scheduler: a directory of `.bpf.c` files, an
/// X-macro list registering them, and a generated Rust enum for the
/// command-line flag that selects between them.
///
/// There are two: mechanisms (what to do with a tracked count) and trackers
/// (how the count is stored). They were separate code until a third tracker
/// was wanted and the tracker axis turned out to be a hand-written pair of
/// if/else branches. The registration machinery already existed for
/// mechanisms and is not specific to them, so it is shared rather than
/// duplicated -- a second copy is a second place for the two to drift apart.
struct Axis {
    /// Directory holding the implementations, relative to the crate root.
    dir: &'static str,
    /// The X-macro the C preprocessor builds its dispatch from.
    list_macro: &'static str,
    /// Name of the generated Rust enum, and of the file it is written to.
    rust_type: &'static str,
    rust_file: &'static str,
    /// Prefix of the per-implementation C symbols, for error messages.
    sym_prefix: &'static str,
    /// Fields per row beyond id and name. Mechanisms carry a function name;
    /// trackers carry a function prefix and a never-undercounts flag.
    extra_fields: usize,
    /// What a row looks like, quoted verbatim in errors.
    row_shape: &'static str,
}

const AXES: &[Axis] = &[
    Axis {
        dir: "src/bpf/mechanisms",
        list_macro: "CMS_MECHANISM_LIST",
        rust_type: "Mechanism",
        rust_file: "mechanisms.rs",
        sym_prefix: "cms_mech_",
        extra_fields: 1,
        row_shape: "X(<id>, <name>, <function>)",
    },
    Axis {
        dir: "src/bpf/trackers",
        list_macro: "CMS_TRACKER_LIST",
        rust_type: "Tracker",
        rust_file: "trackers.rs",
        sym_prefix: "cms_",
        extra_fields: 2,
        row_shape: "X(<id>, <name>, <prefix>, <never_undercounts>)",
    },
];

struct Entry {
    id: u32,
    name: String,
}

/// Parse the rows of an axis's X-macro list out of its index.h.
///
/// That list is the single place an implementation is registered; the
/// kernel-side dispatch is generated from it by the C preprocessor, and the
/// command-line values are generated from it here. Keeping one source means
/// the two cannot disagree.
fn parse_index(axis: &Axis, index: &str) -> Result<Vec<Entry>, String> {
    let marker = format!("#define {}(X)", axis.list_macro);
    let body = index
        .split_once(&marker)
        .ok_or_else(|| format!("{}/index.h: no `{marker}` found", axis.dir))?
        .1;

    let mut out = Vec::new();

    for raw in body.lines() {
        let line = raw.trim().trim_end_matches('\\').trim();
        if line.is_empty() || line.starts_with("/*") || line.starts_with('*') {
            continue;
        }
        let Some(args) = line
            .strip_prefix("X(")
            .and_then(|rest| rest.strip_suffix(')'))
        else {
            break; // end of the macro body
        };

        let fields: Vec<&str> = args.split(',').map(|f| f.trim()).collect();
        if fields.len() != 1 + 1 + axis.extra_fields {
            return Err(format!(
                "{}/index.h: malformed row `{line}`\n  expected: {}",
                axis.dir, axis.row_shape
            ));
        }

        let id: u32 = fields[0].parse().map_err(|_| {
            format!(
                "{}/index.h: row `{line}` has non-numeric id `{}`",
                axis.dir, fields[0]
            )
        })?;

        out.push(Entry {
            id,
            name: fields[1].to_string(),
        });
    }

    if out.is_empty() {
        return Err(format!("{}/index.h: {} is empty", axis.dir, axis.list_macro));
    }

    Ok(out)
}

/// Fail the build on the mistakes the compiler cannot catch.
///
/// The important one is an unlisted file: it compiles perfectly happily,
/// because nothing references it, and the only symptom is a flag value
/// reporting as invalid at run time. Checks that the compiler *does* handle
/// -- such as whether a listed function actually exists -- are deliberately
/// not duplicated here.
fn validate(axis: &Axis, entries: &[Entry], index: &str, dir: &Path) -> Result<(), String> {
    let listed: HashSet<&str> = entries.iter().map(|m| m.name.as_str()).collect();

    if listed.len() != entries.len() {
        return Err(format!(
            "{}/index.h: duplicate name in {}",
            axis.dir, axis.list_macro
        ));
    }

    let ids: HashSet<u32> = entries.iter().map(|m| m.id).collect();
    if ids.len() != entries.len() {
        return Err(format!(
            "{}/index.h: duplicate id in {}",
            axis.dir, axis.list_macro
        ));
    }

    for m in entries {
        if !m.name.chars().all(|c| c.is_ascii_lowercase() || c == '_') {
            return Err(format!(
                "{}/index.h: `{}` is not usable as a command-line value\n  \
                 use lowercase letters and underscores only",
                axis.dir, m.name
            ));
        }

        let file = dir.join(format!("{}.bpf.c", m.name));
        if !file.exists() {
            return Err(format!(
                "{}/index.h lists `{}` but {}/{}.bpf.c does not exist\n  \
                 write the file, or remove the row from {}",
                axis.dir, m.name, axis.dir, m.name, axis.list_macro
            ));
        }

        if !index.contains(&format!("#include \"{}.bpf.c\"", m.name)) {
            return Err(format!(
                "{}/index.h lists `{}` but never includes it\n  add: #include \"{}.bpf.c\"",
                axis.dir, m.name, m.name
            ));
        }
    }

    // The check that earns its keep: a file present but never registered.
    for entry in fs::read_dir(dir).map_err(|e| format!("cannot read {}: {e}", axis.dir))? {
        let entry = entry.map_err(|e| format!("cannot read {}: {e}", axis.dir))?;
        let path = entry.path();
        let Some(file_name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let Some(stem) = file_name.strip_suffix(".bpf.c") else {
            continue;
        };

        if !listed.contains(stem) {
            return Err(format!(
                "{}/{file_name} exists but is not listed in index.h\n  \
                 register it in {} (symbols are {}{stem}_*) and add \
                 `#include \"{file_name}\"`,\n  or delete the file if it is dead",
                axis.dir, axis.list_macro, axis.sym_prefix
            ));
        }
    }

    Ok(())
}

/// Generate the command-line type from the same list the kernel-side
/// dispatch is built from.
fn generate_rust(axis: &Axis, entries: &[Entry]) -> String {
    let mut variants = String::new();
    let mut arms = String::new();

    for m in entries {
        // penalty -> Penalty, test_null -> TestNull
        let variant: String = m
            .name
            .split('_')
            .map(|part| {
                let mut c = part.chars();
                match c.next() {
                    Some(f) => f.to_ascii_uppercase().to_string() + c.as_str(),
                    None => String::new(),
                }
            })
            .collect();

        // Pin the command-line spelling to the registered name. clap's
        // ValueEnum would otherwise derive it from the variant and produce
        // kebab-case, so `test_null` in index.h would have to be spelled
        // `test-null` on the command line -- two spellings for one thing,
        // which is exactly what generating from a single list is meant to
        // prevent. Never came up for mechanisms because every one of those
        // is a single word.
        variants.push_str(&format!(
            "    #[value(name = \"{}\")]\n    {variant},\n",
            m.name
        ));
        arms.push_str(&format!(
            "            {}::{variant} => {},\n",
            axis.rust_type, m.id
        ));
    }

    let ty = axis.rust_type;
    format!(
        "// @generated from {}/index.h -- do not edit.\n\
         //\n\
         // Add one by registering it in that file; this type follows.\n\
         #[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]\n\
         pub enum {ty} {{\n{variants}}}\n\
         \n\
         impl {ty} {{\n\
         \x20   pub fn as_bpf_const(self) -> u32 {{\n\
         \x20       match self {{\n{arms}\x20       }}\n\
         \x20   }}\n\
         }}\n",
        axis.dir
    )
}

fn main() {
    let out = std::env::var("OUT_DIR").unwrap();

    for axis in AXES {
        let dir = Path::new(axis.dir);
        let index_path = dir.join("index.h");

        println!("cargo:rerun-if-changed={}", index_path.display());
        println!("cargo:rerun-if-changed={}", axis.dir);

        let index = fs::read_to_string(&index_path)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", index_path.display()));

        let entries = parse_index(axis, &index).unwrap_or_else(|e| panic!("{e}"));
        validate(axis, &entries, &index, dir).unwrap_or_else(|e| panic!("{e}"));

        fs::write(
            Path::new(&out).join(axis.rust_file),
            generate_rust(axis, &entries),
        )
        .unwrap_or_else(|e| panic!("cannot write generated {}: {e}", axis.rust_file));
    }

    // scx_cargo's enable_skel only watches src/bpf/main.bpf.c itself, not
    // the #include tree under it (trackers/, identity.bpf.c, etc. -- every
    // .bpf.c file in this scheduler except main.bpf.c). Editing any of
    // those without touching main.bpf.c produces a silent no-op build:
    // hit this directly while fixing a real correctness bug, where a
    // rebuild reported success in 0.12s without having recompiled
    // anything. scx_flow and scx_cidland have the same gap, so this isn't
    // specific to this scheduler, but watching the whole tree here is a
    // one-line fix worth having regardless of whether it's fixed upstream.
    println!("cargo:rerun-if-changed=src/bpf");

    scx_cargo::BpfBuilder::new()
        .unwrap()
        .enable_intf("src/bpf/intf.h", "bpf_intf.rs")
        .enable_skel("src/bpf/main.bpf.c", "bpf")
        .build()
        .unwrap();
}
