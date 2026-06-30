#!/usr/bin/env python3
"""Verify that every type with a custom wincode schema implementation is
covered by the `custom_deser_roundtrip` fuzz harness.

A type is considered to have a *custom* schema implementation when it either:

  1. has a hand-written `impl ... SchemaRead/SchemaWrite ... for <Type>`, or
  2. derives the schema but customizes a field with `#[wincode(with = "...")]`
     (in this repo that attribute is feature-gated, i.e. written as
     `#[cfg_attr(feature = "wincode", wincode(with = "..."))]`).

Plain `#[derive(SchemaRead, SchemaWrite)]` types use the default, derived codec
and are intentionally out of scope -- only custom codecs need the extra
roundtrip coverage.

The Rust matching is done with `ast-grep` (https://ast-grep.github.io), not text
regexes, so doc-comment examples and string mentions are ignored automatically;
only real `impl` items and attribute AST nodes are considered. This script just
classifies ast-grep's matches and diffs them against the harness.

Such a type must appear in fuzz/fuzz_targets/custom_deser_roundtrip.rs, unless
it is listed in EXEMPT below (field adapters, generic containers, nested
sub-structs covered transitively, codecs that are not byte-exact by design, and
test-only types).

When CI fails here, either:
  * add a new match arm for the type in custom_deser_roundtrip.rs, or
  * if the type is not a top-level wire payload (it's a helper/adapter/nested
    type covered through its parent, or has no byte-exact round-trip), add it to
    EXEMPT with a one-line reason.

Requires `ast-grep` on PATH (e.g. `npm i -g @ast-grep/cli`).
"""

import json
import os
import shutil
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HARNESS_REL = os.path.join("fuzz", "fuzz_targets", "custom_deser_roundtrip.rs")
HARNESS = os.path.join(REPO_ROOT, HARNESS_REL)

# Matches inside these top-level dirs are ignored (build output, vcs, and the
# harness itself). `target/` is also .gitignored, so ast-grep skips it anyway.
SKIP_TOP_DIRS = {"target", ".git", "fuzz"}

# ast-grep rules. The `regex:` keys are ast-grep node-text constraints (Rust
# regex engine), not Python regexes.
#   - custom-schema-impl: hand-written `impl ... SchemaRead/SchemaWrite for T`.
#     `\b` after Schema(Read|Write) excludes SchemaReadContext / SchemaReadOwned.
#   - wincode-with: a `#[wincode(with = "...")]` attribute (bare or cfg_attr
#     gated), binding $OUTER to the enclosing struct/enum it customizes.
RULES = r"""
id: custom-schema-impl
language: rust
rule:
  kind: impl_item
  all:
    - has: { field: trait, pattern: $TRAIT }
    - has: { field: type, pattern: $TYPE }
constraints:
  TRAIT: { regex: 'Schema(Read|Write)\b' }
---
id: wincode-with
language: rust
rule:
  kind: attribute_item
  regex: 'wincode\(with'
  inside:
    any:
      - kind: struct_item
      - kind: enum_item
    stopBy: end
    has:
      field: name
      pattern: $OUTER
"""

# Types with a custom schema impl / `with` field that are intentionally NOT a
# top-level harness entry point. Keep each reason accurate -- this list is the
# audit trail for why a custom codec is exempt from direct roundtrip fuzzing.
EXEMPT = {
    # Not byte-exact by design: an absent trailing bool reads as the default but
    # is always written back, so re-serialization can grow the payload.
    "UpgradeableLoaderInstruction": "uses OptionalTrailingBool, not byte-exact on round-trip",
    # Nested sub-structs whose custom (ShortVec) field codec is exercised through
    # a fuzzed parent.
    "CompiledInstruction": "nested in messages; ShortVec codec fuzzed via VersionedMessage/VersionedTransaction",
    "MessageAddressTableLookup": "nested in v0 Message; ShortVec codec covered via VersionedMessage",
    "LockoutOffset": "nested in Compact* vote reprs; Leb128Int codec covered via CompactVoteStateUpdate/CompactTowerSync",
    # Test-only structs that exist purely to exercise the codecs in unit tests.
    "ShortVecStruct": "test-only struct in short-vec wincode tests",
    "Dummy": "test-only struct in wincode-varint tests",
}


def base_name(type_spec):
    """Leading type name of a type spec: drop generics and path qualifier.

    e.g. 'containers::Vec<_, ShortU16>' -> 'Vec',
         'OptionalTrailingBool<DEFAULT>' -> 'OptionalTrailingBool'.
    """
    return type_spec.strip().split("<", 1)[0].split("::")[-1].strip()


def with_value(attr_text):
    """The quoted spec from a `... wincode(with = "SPEC") ...` attribute."""
    after = attr_text.split("wincode(with", 1)[1]
    return after.split('"')[1]


def identifiers(text):
    """Set of identifier-like tokens in `text` (no regex)."""
    out = set()
    cur = []
    for ch in text:
        if ch.isalnum() or ch == "_":
            cur.append(ch)
        elif cur:
            out.add("".join(cur))
            cur = []
    if cur:
        out.add("".join(cur))
    return out


def run_ast_grep():
    """Return ast-grep matches for RULES across the repo, as a list of dicts."""
    proc = subprocess.run(
        ["ast-grep", "scan", "--inline-rules", RULES, "--json=compact", REPO_ROOT],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"ast-grep failed:\n{proc.stderr}")
    return json.loads(proc.stdout or "[]")


def scan_repo():
    """Return (candidates, adapter_targets).

    candidates: {type_name: "rel/path.rs:line"} for types with a custom codec.
    adapter_targets: set of type names referenced inside `with = "..."`; these
    are serialization adapters, never payloads.
    """
    candidates = {}
    adapter_targets = set()

    for m in run_ast_grep():
        rel = os.path.relpath(m["file"], REPO_ROOT)
        if rel.split(os.sep, 1)[0] in SKIP_TOP_DIRS:
            continue
        line = m["range"]["start"]["line"] + 1
        single = m.get("metaVariables", {}).get("single", {})
        if m["ruleId"] == "custom-schema-impl":
            name = base_name(single["TYPE"]["text"])
            candidates.setdefault(name, f"{rel}:{line}")
        elif m["ruleId"] == "wincode-with":
            adapter_targets.add(base_name(with_value(m["text"])))
            outer = single["OUTER"]["text"]
            candidates.setdefault(outer, f"{rel}:{line}")
    return candidates, adapter_targets


def main():
    if not shutil.which("ast-grep"):
        print("error: ast-grep not found on PATH (try: npm i -g @ast-grep/cli)", file=sys.stderr)
        return 1
    if not os.path.exists(HARNESS):
        print(f"error: harness not found at {HARNESS}", file=sys.stderr)
        return 1

    covered_names = identifiers(open(HARNESS, encoding="utf-8").read())
    candidates, adapter_targets = scan_repo()

    missing = []
    for name, location in sorted(candidates.items()):
        if name in adapter_targets or name in EXEMPT:
            continue
        if name in covered_names:
            continue
        missing.append((name, location))

    # Surface stale exemptions so the list does not silently rot.
    live = set(candidates) | adapter_targets
    stale = sorted(name for name in EXEMPT if name not in live)
    if stale:
        print("warning: EXEMPT entries no longer found in source:")
        for name in stale:
            print(f"  - {name}")
        print()

    if missing:
        print("error: custom-schema types missing from the fuzz harness")
        print(f"  ({HARNESS_REL}):\n")
        for name, location in missing:
            print(f"  - {name}  (defined at {location})")
        print()
        print("Each type with a hand-written SchemaRead/SchemaWrite impl or a")
        print('#[wincode(with = "...")] field must either get a match arm in the')
        print("harness, or be added to EXEMPT in scripts/check-fuzz-deser-coverage.py")
        print("with a reason (if it's a helper/adapter/nested/non-byte-exact type).")
        return 1

    adapters = len(adapter_targets & set(candidates))
    exempt_hits = sum(1 for n in EXEMPT if n in candidates)
    covered = len(candidates) - adapters - exempt_hits
    print(
        f"ok: all custom-schema payload types are covered by the fuzz harness "
        f"({covered} checked, {exempt_hits} exempt, {adapters} adapters)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
