# Requirement-evidence maps

These files connect requirements to checks. There is one TOML file for each Rust source file,
including `lib.rs`. `lean.toml` contains the Lean theorems. The gate generates the phase-A skeleton
with:

```sh
python3 gates/check_req_map.py --write-skeleton
```

Do not type skeleton entries by hand. The command reads the source files. It writes one `[[entry]]`
for every Rust test, Kani harness, and Lean theorem. Run the command only when you want to replace
the maps with an empty skeleton. It does not keep assigned requirement ids.

Each entry has this form:

```toml
[[entry]]
kind = "test"                 # test, kani, or lean
file = "der-verified/src/integer.rs"
name = "rejects_redundant_leading_zero"
accept = []
reject = []
prove = []
bounded = ""
none = "phase B assigns requirement ids"
```

Use `path` only when one file has more than one declaration with the same kind and name. Its value
is the Rust module path, for example `path = "tests::nested"`.

An id in `accept` means that a conforming input is accepted. An id in `reject` means that a
violating input is rejected. An id in `prove` means that a property is proved for a symbolic domain
or for all inputs. Every id must name an `in` item in `../der.inventory.toml`.
Rows whose inventory `note` contains `umbrella` must not be cited; cite the applicable sentence row
instead.

A test cannot use `prove`. A Lean entry can use only `prove`. A Kani entry that uses `prove` must
state its bound in `bounded`, unless the crate documents the harness as unbounded. Use a short value
such as `len <= 9`. Tests and Lean entries must use `bounded = ""`.

If all three id lists are empty, `none` must explain why. If any list contains an id, use
`none = ""`. Aggregate totals and coverage scores are not allowed in a map.

Run the gate and its observed-red tests with:

```sh
python3 gates/test_check_req_map.py
python3 gates/check_req_map.py
```

`python3 gates/check_req_map.py --report` prints accept, reject, and prove counts for every `in`
inventory item. It does not write a file.
