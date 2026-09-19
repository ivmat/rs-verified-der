#!/bin/bash
# x509_spki / x509_algorithm_identifier control2: the second observed-red control on the
# conjuncts added beyond tiling (spki BIT STRING classification; algid canonical-OID).
# Strings in-file (no shell escaping).
#
# args: SPKI_COPY ALGID_COPY SPKI_OUT ALGID_OUT
set -u
export PATH="$HOME/.cargo/bin:$PATH"
cd "$(dirname "$0")/../.." || exit 2   # crate checkout root
SPKI_COPY="${1:?usage: x509_control2.sh SPKI_COPY ALGID_COPY SPKI_OUT ALGID_OUT}"
ALGID_COPY="${2:?usage: x509_control2.sh SPKI_COPY ALGID_COPY SPKI_OUT ALGID_OUT}"
SPKI_OUT="${3:?usage: x509_control2.sh SPKI_COPY ALGID_COPY SPKI_OUT ALGID_OUT}"
ALGID_OUT="${4:?usage: x509_control2.sh SPKI_COPY ALGID_COPY SPKI_OUT ALGID_OUT}"
mkdir -p "$SPKI_OUT" "$ALGID_OUT"
git checkout -f -q der-verified/src 2>/dev/null; git clean -fdq der-verified/src 2>/dev/null
cp "$SPKI_COPY" der-verified/src/x509_spki.rs
cp "$ALGID_COPY" der-verified/src/x509_algorithm_identifier.rs

# --- spki classification control ---
python3 - <<'PY'
p='der-verified/src/x509_spki.rs'
old='if tlv.tag.class != Class::Universal || tlv.tag.number != BIT_STRING_TAG {'
new='if tlv.tag.class != Class::Universal || false {'
s=open(p).read(); assert s.count(old)==1, f"spki: found {s.count(old)}"
open(p,'w').write(s.replace(old,new,1)); print("spki classification mutated")
PY
cargo kani -Z stubbing --harness x509_spki::proofs::parse_faithful > "$SPKI_OUT/control2-classify-red.log" 2>&1
cp "$SPKI_COPY" der-verified/src/x509_spki.rs

# --- algid canonicality control ---
python3 - <<'PY'
p='der-verified/src/x509_algorithm_identifier.rs'
old='validate_oid(tlv.value).map_err(AlgIdError::BadOid)?;'
new='let _ = tlv.value;'
s=open(p).read(); assert s.count(old)==1, f"algid: found {s.count(old)}"
open(p,'w').write(s.replace(old,new,1)); print("algid canonicality mutated")
PY
cargo kani -Z stubbing --harness x509_algorithm_identifier::proofs::parse_faithful > "$ALGID_OUT/control2-canonical-red.log" 2>&1
cp "$ALGID_COPY" der-verified/src/x509_algorithm_identifier.rs

{
  echo "=== x509 F2 second controls ($(date -u +%FT%TZ)) ==="
  echo "spki classification (||tag.number!=BIT_STRING -> ||false): $(grep -aE 'VERIFICATION:- (SUCCESSFUL|FAILED)' "$SPKI_OUT/control2-classify-red.log"|tail -1)  [want FAILED]"
  echo "  failed: $(grep -aE 'Status: FAILURE' -A1 "$SPKI_OUT/control2-classify-red.log"|grep Description|head -1)"
  echo "algid canonicality (drop validate_oid): $(grep -aE 'VERIFICATION:- (SUCCESSFUL|FAILED)' "$ALGID_OUT/control2-canonical-red.log"|tail -1)  [want FAILED]"
  echo "  failed: $(grep -aE 'Status: FAILURE' -A1 "$ALGID_OUT/control2-canonical-red.log"|grep Description|head -1)"
}
touch "$SPKI_OUT/.control2-done" "$ALGID_OUT/.control2-done"
