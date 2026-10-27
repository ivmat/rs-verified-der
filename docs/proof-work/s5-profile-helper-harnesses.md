# profile.rs: the three symbolic helper harnesses (parked, S5)

Status: **not in the crate, not part of any gate, not evidence for any requirement row.** They were
removed from `der-verified/src/profile.rs` (`mod proofs`) in the S4b cost fix because none of them
finishes inside the 20 GB cap. The facts they decided are listed at the end; the `docs/requirements/evidence/profile.toml`
entries for them are gone.

## Measured result (Kani, 20 GB `MemoryMax`, swap 0, sequential, branch `s4b-b1-cost` at f1a29f4)

| harness | result |
|---|---|
| `has_repeated_leading_oid_is_total` | OOM-killed at 20 GB after 4 min |
| `name_has_repeated_attribute_type_is_total` | OOM-killed at 20 GB after 12 min |
| `has_repeated_leading_oid_is_exact_on_three_elements` | OOM-killed at 20 GB after 4 min |

Two concrete-input harnesses (`rules_5_to_7_helpers_return_false_on_the_isolation_inputs`,
`rules_5_to_7_end_to_end_on_specimens`) were OOM-killed at the same cap (6 and 10 min); they are now unit tests
in `profile.rs` (`mod tests`). That even concrete inputs blow up shows the cost is the composition, not the
symbolic domain: about 73,000 verification conditions, dominated by the unwinding of `decode_length`,
`decode_tag` and `memcmp` inside the nested `Elements` walks of `has_repeated_leading_oid` (its two loops, `.0` and
`.1`: the outer walk and the cloned inner walk). Tuning the unwind bounds does not help: the bounds are already
the minimum the inputs need.

## S5 plan

1. Stub `decode_tlv` (or `Elements::next`) inside these three harnesses with its proven postcondition, the way
   `x509_name::proofs::validate_never_panics` stubs `validate_rdn` (DECISIONS D26). The postcondition to
   state is the one `tlv::proofs::decode_tlv_structure` already proves: an accepted TLV consumes exactly header plus
   declared length, its value borrow is those octets, and the total never exceeds the input. The stub removes the
   `decode_length`/`decode_tag`/`memcmp`-per-step unwinding; what is left is the pair loop and the OID content
   comparison.
2. Re-measure with the same 20 GB cap. If it still runs out of memory, split further: prove `leading_oid`
   (already `leading_oid_is_exact`, cheap) and the pair loop over a stubbed `leading_oid` returning a symbolic
   `Option<&[u8]>`; then the walk, then the composition.
3. Re-enter the harnesses in `profile.rs` and in `profile.toml` only with a measured pass.
4. Until then the stubs `stub_any_outcome`, `stub_steered_by_bit0` and `stub_steered_by_bit1` in `profile.rs`
   have an undischarged obligation for `has_repeated_leading_oid` (it is total and returns a `bool`). The unit tests
   in `profile.rs` decide the helpers on concrete inputs; they do not discharge that obligation.

## Source

Support code the harnesses use. `same_oid` and `raw_bytes_differ` stay in `profile.rs` (`leading_oid_is_exact`
uses them); the rest is moved here.

```rust
/// Octets of one element of the framed shape: identifier octet, length octet `06`, six content octets.
const ELEM: usize = 8;

/// Reference for the OID child of a six-octet element content: the content is a TLV `06 k <k octets>`
/// iff its first octet is `06` and `k <= 4` (a longer `k`, or any long-form length, cannot fit in six
/// octets, so the TLV is truncated). Written from the DER layout, not from `decode_tlv`.
fn child_oid(content: &[u8; 6]) -> Option<&[u8]> {
    if content[0] == 0x06 && content[1] <= 4 {
        Some(&content[2..2 + content[1] as usize])
    } else {
        None
    }
}

/// Reference for `leading_oid` on the framed shape: the element must be tagged `30` (UNIVERSAL 16,
/// constructed) and have an OID child.
fn ref_leading<'a>(tag: u8, content: &'a [u8; 6]) -> Option<&'a [u8]> {
    if tag == 0x30 {
        child_oid(content)
    } else {
        None
    }
}

/// How many leading elements of the framed shape a walk over `len` octets visits: an element is
/// visited iff it lies wholly inside `len` and every element before it was visited and its
/// identifier octet is a single-octet form. An identifier octet whose low five bits are `1f` starts
/// the high-tag-number form, which reads the following length octet `06` as its tag number
/// (6 <= 30, non-minimal) and is rejected, so the walk stops there; a cut element is truncated
/// and the walk stops there.
fn visited(tags: &[u8; 3], len: usize) -> usize {
    let mut n = 0;
    while n < 3 && (n + 1) * ELEM <= len && tags[n] & 0x1f != 0x1f {
        n += 1;
    }
    n
}

/// Reference for `has_repeated_leading_oid` on the framed shape: two visited elements have the same
/// leading OID content octets.
fn ref_has_repeat(tags: &[u8; 3], content: &[[u8; 6]; 3], visited: usize) -> bool {
    let mut i = 0;
    while i < visited {
        if let Some(id) = ref_leading(tags[i], &content[i]) {
            let mut j = i + 1;
            while j < visited {
                if same_oid(ref_leading(tags[j], &content[j]), Some(id)) {
                    return true;
                }
                j += 1;
            }
        }
        i += 1;
    }
    false
}

/// Write one element of the framed shape at `buf[at..at + ELEM]`.
fn put_elem(buf: &mut [u8], at: usize, tag: u8, content: &[u8; 6]) {
    buf[at] = tag;
    buf[at + 1] = 6;
    buf[at + 2..at + ELEM].copy_from_slice(content);
}
```

### `has_repeated_leading_oid_is_exact_on_three_elements`

```rust
/// `has_repeated_leading_oid` is exact on the framed shape: up to three elements of 8 octets each
/// (identifier octet symbolic, length octet `06`, six symbolic content octets), cut at a symbolic
/// total length `0..=24`. It returns `true` iff two VISITED elements (`visited`) both have an id
/// (UNIVERSAL 16 constructed, first child an OID of `k <= 4` content octets) and the ids are equal
/// octet by octet (`ref_has_repeat`, using `raw_bytes_differ`). Pairs are compared whether
/// adjacent or not; a repeat behind a cut or rejected element is not seen; an element with another
/// tag, or whose first child is not an OID, takes no part; ids of different length are different.
/// No restriction on any octet: an identifier octet with low bits `1f` is modelled (the walk
/// stops), and the content octets are unconstrained, so truncated and non-OID first children are
/// included.
///
/// Bounds: at most 3 elements of the fixed 8-octet stride (so at most 3 pairs); ids of at most 4
/// octets. Longer lists and longer ids are covered by the unit tests only; the pair loop is the same
/// at any length. Unwind 7: see the P8 block comment.
#[kani::proof]
#[kani::unwind(7)]
fn has_repeated_leading_oid_is_exact_on_three_elements() {
    let tags: [u8; 3] = kani::any();
    let content: [[u8; 6]; 3] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= 3 * ELEM);
    let mut buf = [0u8; 3 * ELEM];
    put_elem(&mut buf, 0, tags[0], &content[0]);
    put_elem(&mut buf, ELEM, tags[1], &content[1]);
    put_elem(&mut buf, 2 * ELEM, tags[2], &content[2]);
    let r = has_repeated_leading_oid(&buf[..len]);
    let seen = visited(&tags, len);
    assert!(r == ref_has_repeat(&tags, &content, seen));
    let l0 = ref_leading(tags[0], &content[0]);
    let l1 = ref_leading(tags[1], &content[1]);
    let l2 = ref_leading(tags[2], &content[2]);
    kani::cover(r && seen == 2, "a repeat between two framed elements is found");
    kani::cover(
        r && seen == 3 && l0.is_some() && same_oid(l0, l2) && !same_oid(l0, l1) && !same_oid(l1, l2),
        "a non-adjacent repeat (elements 0 and 2, a different element between) is found",
    );
    kani::cover(
        !r && seen == 3 && l0.is_some() && l1.is_some() && l2.is_some(),
        "three framed elements with three different ids: no repeat",
    );
    kani::cover(
        !r && seen == 2 && l0.is_some() && same_oid(l0, l2),
        "an id repeated by an element the walk never reaches (cut or rejected) is not a repeat",
    );
    kani::cover(
        r && seen >= 2 && matches!(l0, Some(o) if o.len() == 2) && same_oid(l0, l1),
        "two-octet ids are compared octet by octet",
    );
    kani::cover(
        !r && seen >= 2
            && matches!((l0, l1), (Some(p), Some(q)) if p.len() == 2 && q.len() == 2 && p[0] == q[0] && p[1] != q[1]),
        "ids that differ in the last octet only are not a repeat",
    );
    kani::cover(
        !r && seen >= 2 && l0.is_some() && tags[1] != 0x30 && same_oid(child_oid(&content[1]), l0),
        "the same id bytes inside an element of another tag take no part",
    );
    kani::cover(
        !r && seen >= 2 && matches!((l0, l1), (Some(p), Some(q)) if p.len() != q.len() && p.len() > 0 && q.len() > 0 && p[0] == q[0]),
        "an id that is a strict prefix of another is not a repeat",
    );
}
```

### `has_repeated_leading_oid_is_total`

```rust
/// `has_repeated_leading_oid` is total and `false` on every short content: for any octets and any
/// length `0..=6` it neither panics nor overflows, and returns `false` (two elements that both
/// have an id need at least 8 octets: two `30 02 06 00`). RAW window shape, no octet restricted.
///
/// Bounds: content window `0..=6` octets. This is the totality half of the proof; the exact
/// half for longer content is `has_repeated_leading_oid_is_exact_on_three_elements`.
#[kani::proof]
#[kani::unwind(7)]
fn has_repeated_leading_oid_is_total() {
    let back: [u8; 6] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= 6);
    let r = has_repeated_leading_oid(&back[..len]);
    assert!(!r);
    kani::cover(
        matches!(decode_tlv(&back[..len]), Ok((_, used)) if used < len),
        "the walk gets past its first element (a second element or a leftover is examined)",
    );
    kani::cover(
        matches!(decode_tlv(&back[..len]), Ok((t, _)) if leading_oid(&t).is_some()),
        "a first element with an id is reached, so the comparison with later elements runs",
    );
}
```

### `name_has_repeated_attribute_type_is_total`

```rust
/// `name_has_repeated_attribute_type` is total and `false` on every short span: for any octets and
/// any length `0..=6` it neither panics nor overflows, and returns `false` (a repeat needs the
/// envelope, an RDN and two elements: at least 12 octets). RAW window shape, no octet restricted,
/// the real inner comparison (no stub).
///
/// Bounds: span window `0..=6` octets. Unwind 7: see the P8 block comment.
#[kani::proof]
#[kani::unwind(7)]
fn name_has_repeated_attribute_type_is_total() {
    let back: [u8; 6] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= 6);
    let r = name_has_repeated_attribute_type(&back[..len]);
    assert!(!r);
    kani::cover(
        matches!(decode_sequence_tlv_strict(&back[..len]), Ok(c) if c.len() >= 2),
        "a Name envelope with content is framed, so the RDN walk runs",
    );
    kani::cover(
        matches!(decode_sequence_tlv_strict(&back[..len]), Ok(c) if matches!(decode_tlv(c), Ok((t, _)) if t.tag.number == SET_TAG)),
        "a first RDN that is a SET is reached, so its element comparison runs",
    );
}
```

## Facts these harnesses decided (now decided by unit tests only, on concrete inputs)

- `has_repeated_leading_oid`: two elements of the same content have equal leading ids iff reported, for lists of at
  most 3 elements with ids of at most 4 octets (rows RFC5280-4.2-c, X501-9.3-g, PROF-P-12, PROF-P-14);
  total and `false` on every content of 0 to 6 octets.
- `name_has_repeated_attribute_type`: total and `false` on every span of 0 to 6 octets.
