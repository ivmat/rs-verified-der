# Test-gap report

This file is generated. Do not edit it by hand.
Regenerate it with `python3 gates/gen_req_gaps.py`.
`python3 gates/gen_req_gaps.py --check` fails if this file is stale.

## What this report is

The owner ruled that every requirement must first be covered by tests. Proofs come
after. This report judges TEST coverage for each `in` row of
`docs/requirements/der.inventory.toml`. Kani and Lean evidence is shown next to the
tests. It never replaces a test that a row needs. This is a working report for step S4.
It is not an acceptance manifest and it claims no assurance band.

Inputs: the inventory, `docs/requirements/evidence/*.toml`,
`docs/requirements/obligations.toml`, the `pub fn encode` functions in
`der-verified/src`, and `check_fast.sh` (for the role `gate`).

## Obligation rule

- `SAFE-*` rows need a proof (Kani or Lean). Tests are shown but cannot discharge them.
- `API-*` rows need a human review. They have no test obligation.
- `CODEC-*-reject-nonder` and `CODEC-*-unique` rows need a `reject` test.
- `CODEC-*-encode-decode` and `CODEC-*-decode-encode` rows need an `accept` test.
- `PROF-*` rows need an `accept` test and a `reject` test.
- Standards rows use the `side` field. A decoder side (decoder, both, relying-party,
  issuer) needs an `accept` test and a `reject` test.
- An encoder side (encoder, both) needs an `accept` test in a module that has an
  encoder. This applies only if one of the row's modules has a `pub fn encode`.
  Limit: the maps do not show which tests call the encoder. The check is a lower bound.
- Umbrella rows are skipped. Their sentence rows carry the evidence.
- An override may use the role `gate` with `gate = "gates/<file>.py"`. It is for a rule that a
  static source gate decides on every commit. The role is MET if the file exists and
  `check_fast.sh` runs it, and MISSING otherwise.
- `docs/requirements/obligations.toml` has 38 override rows. Each has a reason.

Role status: MET (a test exists), PROOF-ONLY (only Kani or Lean exists in that role),
MISSING, MISSING-ENC (accept tests exist but none is in an encoder module), REVIEW.
For the role `gate`: MET (the gate file exists and `check_fast.sh` runs it) or MISSING.

## Totals

Rows judged: 336. Umbrella rows skipped: 16.

| status | rows | meaning |
|---|---|---|
| COVERED | 327 | every needed role has a test (or, for the role `gate`, a gate that check_fast.sh runs) |
| PARTIAL | 0 | some needed role has a test, not all |
| PROOF-ONLY | 0 | no needed role has a test, but Kani or Lean evidence exists |
| NONE | 0 | no evidence in any needed role |
| REVIEW | 9 | only a human review is needed |

Rows that are not COVERED and carry a known gap (`gap:` note): 0.

## STD: External standards

### STD source X690

| id | title | needs | role status | status | test/kani/lean | known gap |
|---|---|---|---|---|---|---|
| X690-8.1.3.6.1 | Indefinite length uses the single octet 0x80 | accept, reject | accept:MET, reject:MET | COVERED | 2/0/1 |  |
| X690-8.3.2 | INTEGER minimal sign representation | accept, reject | accept:MET, reject:MET | COVERED | 21/10/3 |  |
| X690-8.6 | BIT STRING permits primitive or constructed form | accept, reject | accept:MET, reject:MET | COVERED | 9/0/0 |  |
| X690-8.19 | OID contents concatenate ordered subidentifier encodings | accept, reject | accept:MET, reject:MET | COVERED | 2/0/0 |  |
| X690-10.1 | DER definite minimal lengths | accept, reject | accept:MET, reject:MET | COVERED | 45/3/11 |  |
| X690-10.2 | DER primitive string forms | accept, reject | accept:MET, reject:MET | COVERED | 24/25/0 |  |
| X690-11.1 | DER BOOLEAN true octet | accept, reject | accept:MET, reject:MET | COVERED | 5/1/0 |  |
| X690-11.5 | DER default values omitted | accept, reject | accept:MET, reject:MET | COVERED | 6/1/0 |  |
| X690-11.6 | DER SET OF ordering | accept, reject | accept:MET, reject:MET | COVERED | 9/10/0 |  |
| X690-8.1.2.6 | CHOICE uses the selected alternative tag | accept, reject | accept:MET, reject:MET | COVERED | 8/6/0 |  |
| X690-8.1.3.1 | Length octets have definite and indefinite forms | accept, reject | accept:MET, reject:MET | COVERED | 2/0/0 |  |
| X690-8.19.2-a | Each OID subidentifier uses one or more octets | accept, reject | accept:MET, reject:MET | COVERED | 2/1/1 |  |
| X690-8.19.2-b | OID continuation bits mark all but the final octet | accept, reject | accept:MET, reject:MET | COVERED | 2/1/1 |  |
| X690-8.23.3-a | Restricted string identifiers use their universal tag n... | accept, reject | accept:MET, reject:MET | COVERED | 9/7/0 |  |
| X690-8.23.3-b | Restricted string octet values follow their character m... | accept, reject | accept:MET, reject:MET | COVERED | 20/24/0 |  |
| X690-10 | DER combines basic encoding with clauses 10 and 11 | review | review:REVIEW | REVIEW | 0/0/0 |  |
| X690-8.1.1.1 | Encoding components | accept, reject | accept:MET, reject:MET | COVERED | 3/1/1 |  |
| X690-8.1.1.2 | End-of-contents appears only with an indefinite length | accept, reject | accept:MET, reject:MET | COVERED | 2/4/0 |  |
| X690-8.1.2.1 | Tag class and number | accept, reject | accept:MET, reject:MET | COVERED | 4/1/4 |  |
| X690-8.1.2.2 | Low tag form | accept, reject | accept:MET, reject:MET | COVERED | 11/2/5 |  |
| X690-8.1.2.4 | High tag form | accept, reject | accept:MET, reject:MET | COVERED | 4/2/0 |  |
| X690-8.1.2.4.1 | High tag leading octet | accept, reject | accept:MET, reject:MET | COVERED | 4/2/0 |  |
| X690-8.1.2.4.2 | Base 128 tag digits and minimal first digit | accept, reject | accept:MET, reject:MET | COVERED | 9/3/6 |  |
| X690-8.1.2.5 | Primitive and constructed bit | accept, reject | accept:MET, reject:MET | COVERED | 12/6/5 |  |
| X690-8.1.3.2 | Primitive definite length | accept, reject | accept:MET, reject:MET | COVERED | 3/0/0 |  |
| X690-8.1.3.3 | Definite length content size | accept, reject | accept:MET, reject:MET | COVERED | 39/5/7 |  |
| X690-8.1.3.4 | Short length | accept, reject | accept:MET, reject:MET | COVERED | 11/1/3 |  |
| X690-8.1.3.5 | Long length and forbidden ff | accept, reject | accept:MET, reject:MET | COVERED | 14/4/5 |  |
| X690-8.1.4 | Contents octets | accept, reject | accept:MET, reject:MET | COVERED | 3/1/1 |  |
| X690-8.2.1 | Primitive BOOLEAN one octet | accept, reject | accept:MET, reject:MET | COVERED | 8/8/0 |  |
| X690-8.2.2 | BOOLEAN abstract values | accept, reject | accept:MET, reject:MET | COVERED | 2/1/0 |  |
| X690-8.3.1 | Primitive INTEGER | accept, reject | accept:MET, reject:MET | COVERED | 9/5/0 |  |
| X690-8.3.3 | Signed two complement INTEGER | accept, reject | accept:MET, reject:MET | COVERED | 9/1/1 |  |
| X690-8.4 | ENUMERATED uses INTEGER encoding | accept, reject | accept:MET, reject:MET | COVERED | 3/2/0 |  |
| X690-8.6.2 | BIT STRING initial octet | accept, reject | accept:MET, reject:MET | COVERED | 4/5/0 |  |
| X690-8.6.2.1 | BIT STRING bit order | accept, reject | accept:MET, reject:MET | COVERED | 3/0/0 |  |
| X690-8.6.2.2 | Unused count zero to seven | accept, reject | accept:MET, reject:MET | COVERED | 7/5/0 |  |
| X690-8.6.2.3 | Empty BIT STRING | accept, reject | accept:MET, reject:MET | COVERED | 4/5/0 |  |
| X690-8.7.1 | OCTET STRING form | accept, reject | accept:MET, reject:MET | COVERED | 4/1/0 |  |
| X690-8.7.2 | Primitive OCTET STRING contents | accept, reject | accept:MET, reject:MET | COVERED | 5/3/0 |  |
| X690-8.8.1 | Primitive NULL | accept, reject | accept:MET, reject:MET | COVERED | 2/5/0 |  |
| X690-8.8.2 | Empty NULL contents | accept, reject | accept:MET, reject:MET | COVERED | 3/1/0 |  |
| X690-8.9.1 | Constructed SEQUENCE | accept, reject | accept:MET, reject:MET | COVERED | 17/10/0 |  |
| X690-8.9.2 | SEQUENCE components in definition order | accept, reject | accept:MET, reject:MET | COVERED | 105/23/0 |  |
| X690-8.9.3 | OPTIONAL and DEFAULT components | accept, reject | accept:MET, reject:MET | COVERED | 13/3/0 |  |
| X690-8.10.1 | Constructed SEQUENCE OF | accept, reject | accept:MET, reject:MET | COVERED | 12/12/0 |  |
| X690-8.10.2 | Complete homogeneous encodings | accept, reject | accept:MET, reject:MET | COVERED | 13/12/0 |  |
| X690-8.10.3 | SEQUENCE OF order | accept | accept:MET | COVERED | 1/0/0 |  |
| X690-8.12.1 | Constructed SET OF | accept, reject | accept:MET, reject:MET | COVERED | 15/14/0 |  |
| X690-8.12.2 | SET OF homogeneous encodings | accept, reject | accept:MET, reject:MET | COVERED | 4/2/0 |  |
| X690-8.14.2 | Tagged base encoding | accept, reject | accept:MET, reject:MET | COVERED | 21/0/0 |  |
| X690-8.14.3 | EXPLICIT complete constructed wrapper | accept, reject | accept:MET, reject:MET | COVERED | 35/2/0 |  |
| X690-8.19.1 | Primitive OID | accept, reject | accept:MET, reject:MET | COVERED | 4/7/0 |  |
| X690-8.19.2 | Minimal base 128 OID subidentifiers | accept, reject | accept:MET, reject:MET | COVERED | 8/2/1 |  |
| X690-8.19.3 | OID component count | accept, reject | accept:MET, reject:MET | COVERED | 2/1/1 |  |
| X690-8.19.4 | First two OID arcs combine | accept | accept:MET | COVERED | 1/0/0 |  |
| X690-8.19.5 | Subsequent OID arcs | accept | accept:MET | COVERED | 1/0/0 |  |
| X690-8.23.3 | Restricted strings as octet strings | accept, reject | accept:MET, reject:MET | COVERED | 3/1/0 |  |
| X690-8.23.4 | Numeric and Printable mapping | accept, reject | accept:MET, reject:MET | COVERED | 7/8/0 |  |
| X690-8.23.5 | Registered encodings for the supported restricted strings | accept, reject | accept:MET, reject:MET | COVERED | 3/0/0 |  |
| X690-8.23.5.1 | Supported restricted strings limit registered escapes | accept, reject | accept:MET, reject:MET | COVERED | 2/2/0 |  |
| X690-8.23.5.2 | Supported restricted strings begin with their assigned... | accept, reject | accept:MET, reject:MET | COVERED | 3/0/0 |  |
| X690-8.23.5.3 | Supported restricted strings obey the explicit-escape t... | accept, reject | accept:MET, reject:MET | COVERED | 3/3/0 |  |
| X690-8.23.5.4 | Supported restricted strings use announcers only when a... | accept, reject | accept:MET, reject:MET | COVERED | 3/1/0 |  |
| X690-8.23.9 | UTF8String permits most C0 and C1 controls | accept, reject | accept:MET, reject:MET | COVERED | 4/5/0 |  |
| X690-8.23.10 | UTF8String octets | accept, reject | accept:MET, reject:MET | COVERED | 14/4/0 |  |
| X690-11.2.1 | Zero unused padding bits | accept, reject | accept:MET, reject:MET | COVERED | 9/5/0 |  |
| X690-11.7.1 | GeneralizedTime Z suffix | accept, reject | accept:MET, reject:MET | COVERED | 9/4/0 |  |
| X690-11.7.2 | GeneralizedTime seconds | accept, reject | accept:MET, reject:MET | COVERED | 9/4/0 |  |
| X690-11.7.3 | GeneralizedTime fractional zeros | accept, reject | accept:MET, reject:MET | COVERED | 9/4/0 |  |
| X690-11.7.4 | GeneralizedTime decimal point | accept, reject | accept:MET, reject:MET | COVERED | 6/4/0 |  |
| X690-11.7.5 | GeneralizedTime midnight | accept, reject | accept:MET, reject:MET | COVERED | 5/4/0 |  |
| X690-11.8.1 | UTCTime Z suffix | accept, reject | accept:MET, reject:MET | COVERED | 9/5/0 |  |
| X690-11.8.2 | UTCTime seconds | accept, reject | accept:MET, reject:MET | COVERED | 7/4/0 |  |
| X690-11.8.3 | UTCTime midnight | accept, reject | accept:MET, reject:MET | COVERED | 6/4/0 |  |
| X690-8.1.5 | Definite encodings have no EOC trailer | accept, reject | accept:MET, reject:MET | COVERED | 6/6/0 |  |
| X690-8.3.1-a | INTEGER payload has at least one octet | accept, reject | accept:MET, reject:MET | COVERED | 10/3/3 |  |
| X690-8.5.1 | REAL requires the primitive form bit | accept, reject | accept:MET, reject:MET | COVERED | 2/5/0 |  |
| X690-8.13 | CHOICE carries the selected alternative directly | accept, reject | accept:MET, reject:MET | COVERED | 7/6/0 |  |
| X690-8.15 | An open-type value is exactly one framed TLV | accept, reject | accept:MET, reject:MET | COVERED | 21/10/0 |  |
| X690-8.16.1 | INSTANCE OF requires the constructed form bit | accept, reject | accept:MET, reject:MET | COVERED | 1/4/0 |  |
| X690-8.17.1 | EMBEDDED PDV requires the constructed form bit | accept, reject | accept:MET, reject:MET | COVERED | 1/4/0 |  |
| X690-8.18.1 | EXTERNAL requires the constructed form bit | accept, reject | accept:MET, reject:MET | COVERED | 1/5/0 |  |
| X690-8.20.1 | Relative OID requires the primitive form bit | accept, reject | accept:MET, reject:MET | COVERED | 2/4/0 |  |
| X690-8.21.1 | OID IRI requires the primitive form bit | accept, reject | accept:MET, reject:MET | COVERED | 1/5/0 |  |
| X690-8.22.1 | Relative OID IRI requires the primitive form bit | accept, reject | accept:MET, reject:MET | COVERED | 2/5/0 |  |
| X690-8.23.9a | UTF8String excludes ISO 2022 announcer escapes | accept, reject | accept:MET, reject:MET | COVERED | 3/5/0 |  |
| X690-8.23.9b | UTF8String excludes code-set designation and identifica... | accept, reject | accept:MET, reject:MET | COVERED | 2/5/0 |  |
| X690-8.23.9c | UTF8String excludes ISO 2022 invocation controls | accept, reject | accept:MET, reject:MET | COVERED | 3/5/0 |  |
| X690-8.23.9d | UTF8String coding stays within ISO 10646 | accept, reject | accept:MET, reject:MET | COVERED | 2/5/0 |  |
| X690-8.23.9f | UTF8String excludes switches into ISO 2022 coding | accept, reject | accept:MET, reject:MET | COVERED | 2/5/0 |  |
| X690-8.23.10-a | UTF8String uses shortest UTF8 without announcers or esc... | accept, reject | accept:MET, reject:MET | COVERED | 12/3/0 |  |
| X690-8.24.1 | CHARACTER STRING requires the constructed form bit | accept, reject | accept:MET, reject:MET | COVERED | 1/4/0 |  |
| X690-8.26.1.1 | TIME requires the primitive form bit | accept, reject | accept:MET, reject:MET | COVERED | 2/4/0 |  |
| X690-8.26.2.1 | DATE requires the primitive form bit | accept, reject | accept:MET, reject:MET | COVERED | 2/5/0 |  |
| X690-8.26.3.1 | TIME-OF-DAY requires the primitive form bit | accept, reject | accept:MET, reject:MET | COVERED | 1/5/0 |  |
| X690-8.26.4.1 | DATE-TIME requires the primitive form bit | accept, reject | accept:MET, reject:MET | COVERED | 1/5/0 |  |
| X690-8.26.5.1 | DURATION requires the primitive form bit | accept, reject | accept:MET, reject:MET | COVERED | 2/5/0 |  |
| X690-8.1.1.4 | Subtype constraints and extension markers do not alter... | review | review:REVIEW | REVIEW | 0/0/0 |  |
| X690-7.4 | DER admits no alternate encoding for one value | accept, reject | accept:MET, reject:MET | COVERED | 67/23/13 |  |

### STD source RFC5280

| id | title | needs | role status | status | test/kani/lean | known gap |
|---|---|---|---|---|---|---|
| RFC5280-4.1.2.5.1 | Certificate UTCTime seconds and zone | accept, reject | accept:MET, reject:MET | COVERED | 10/6/0 |  |
| RFC5280-4.1.2.5.2 | Certificate GeneralizedTime excludes fractional seconds | accept, reject | accept:MET, reject:MET | COVERED | 11/3/0 |  |
| RFC5280-4.1 | Certificate has three ordered fields | accept, reject | accept:MET, reject:MET | COVERED | 10/0/0 |  |
| RFC5280-4.1-a | TBSCertificate contains the signed certificate body | accept, reject | accept:MET, reject:MET | COVERED | 15/0/0 |  |
| RFC5280-4.1-b | Version enumerates v1 through v3 | accept, reject | accept:MET, reject:MET | COVERED | 10/0/0 |  |
| RFC5280-4.1-c | Certificate serial number is an INTEGER | accept, reject | accept:MET, reject:MET | COVERED | 5/0/0 |  |
| RFC5280-4.1-d | Validity contains notBefore and notAfter | accept, reject | accept:MET, reject:MET | COVERED | 9/7/0 |  |
| RFC5280-4.1-e | Time selects UTCTime or GeneralizedTime | accept, reject | accept:MET, reject:MET | COVERED | 7/6/0 |  |
| RFC5280-4.1-f | SubjectPublicKeyInfo contains algorithm and key bits | accept, reject | accept:MET, reject:MET | COVERED | 13/1/0 |  |
| RFC5280-4.1-g | Extensions is a nonempty sequence | accept, reject | accept:MET, reject:MET | COVERED | 7/6/0 |  |
| RFC5280-4.1-h | Extension carries identifier criticality and value | accept, reject | accept:MET, reject:MET | COVERED | 19/5/0 |  |
| RFC5280-4.1.1.2 | Outer and inner signature algorithms match | accept, reject | accept:MET, reject:MET | COVERED | 5/2/0 |  |
| RFC5280-4.1.1.2-a | AlgorithmIdentifier contains OID and optional parameters | accept, reject | accept:MET, reject:MET | COVERED | 14/1/0 |  |
| RFC5280-4.1.2.1 | Extensions require certificate version three | accept, reject | accept:MET, reject:MET | COVERED | 6/2/0 |  |
| RFC5280-4.1.2.1-d | Decoders recognize version three | accept | accept:MET | COVERED | 1/0/0 |  |
| RFC5280-4.1.2.2-c | Decoders handle serials through twenty octets | accept | accept:MET | COVERED | 2/0/0 |  |
| RFC5280-4.1.2.2-e | Decoders gracefully handle nonpositive serials | accept | accept:MET | COVERED | 1/0/0 |  |
| RFC5280-4.1.2.3 | Inner and outer signature algorithms match | accept, reject | accept:MET, reject:MET | COVERED | 5/2/0 |  |
| RFC5280-4.1.2.4 | Issuer name is nonempty | accept, reject | accept:MET, reject:MET | COVERED | 4/1/0 |  |
| RFC5280-4.1.2.4-a | Name is an RDN sequence | accept, reject | accept:MET, reject:MET | COVERED | 5/4/0 |  |
| RFC5280-4.1.2.4-b | RDN contains at least one attribute | accept, reject | accept:MET, reject:MET | COVERED | 6/5/0 |  |
| RFC5280-4.1.2.4-c | Attribute carries type and value | accept, reject | accept:MET, reject:MET | COVERED | 10/9/0 |  |
| RFC5280-4.1.2.4-e | Structurally accept required issuer attributes | accept | accept:MET | COVERED | 2/0/0 |  |
| RFC5280-4.1.2.4-f | Structurally accept standard issuer attributes | accept | accept:MET | COVERED | 3/0/0 |  |
| RFC5280-4.1.2.4-g | Structurally accept additional issuer attributes | accept | accept:MET | COVERED | 1/0/0 |  |
| RFC5280-4.1.2.4-h | Structurally accept domainComponent attributes | accept | accept:MET | COVERED | 1/0/0 |  |
| RFC5280-4.1.2.5 | Validity year selects its time encoding | accept, reject | accept:MET, reject:MET | COVERED | 15/4/0 |  |
| RFC5280-4.1.2.5-a | Decoders accept either Time alternative | accept | accept:MET | COVERED | 4/5/0 |  |
| RFC5280-4.1.2.5.1-b | UTCTime years use the profile pivot | accept | accept:MET | COVERED | 1/1/0 |  |
| RFC5280-4.1.2.5.1c | Years fifty through ninety-nine mean 19YY | accept | accept:MET | COVERED | 1/1/0 |  |
| RFC5280-4.1.2.5.1d | Years zero through forty-nine mean 20YY | accept | accept:MET | COVERED | 1/1/0 |  |
| RFC5280-4.1.2.5.2-a | GeneralizedTime uses Zulu and includes seconds | accept, reject | accept:MET, reject:MET | COVERED | 7/5/0 |  |
| RFC5280-4.1.2.6-b | Nonempty subjects contain distinguished names | accept, reject | accept:MET, reject:MET | COVERED | 6/0/0 |  |
| RFC5280-4.1.2.6-d | Structurally accept required subject attributes | accept | accept:MET | COVERED | 2/0/0 |  |
| RFC5280-4.1.2.6-e | Structurally accept recommended subject attributes | accept | accept:MET | COVERED | 3/0/0 |  |
| RFC5280-4.1.2.8-b | CAs omit unique identifiers | accept, reject | accept:MET, reject:MET | COVERED | 2/0/0 |  |
| RFC5280-4.1.2.9 | Extensions appear only in version three | accept, reject | accept:MET, reject:MET | COVERED | 6/2/0 |  |
| RFC5280-4.2-c | Each extension identifier appears at most once | accept, reject | accept:MET, reject:MET | COVERED | 5/0/0 |  |
| RFC5280-4.1.1.3-a | The certificate signature value is a BIT STRING | accept, reject | accept:MET, reject:MET | COVERED | 5/0/0 |  |
| RFC5280-B-size-upper-bound | Implementations choose practical bounds for ASN.1 MAX | accept | accept:MET | COVERED | 2/0/0 |  |
| RFC5280-B-printable-specials | PrintableString does not admit at-sign or underscore | accept, reject | accept:MET, reject:MET | COVERED | 4/4/0 |  |

### STD source X680

| id | title | needs | role status | status | test/kani/lean | known gap |
|---|---|---|---|---|---|---|
| X680-8a | Tag numbers are nonnegative integers | accept | accept:MET | COVERED | 1/1/0 |  |
| X680-8b | The universal tag table assigns built-in type tags | accept | accept:MET | COVERED | 1/2/0 |  |
| X680-18d | BOOLEAN has exactly TRUE and FALSE values | accept, reject | accept:MET, reject:MET | COVERED | 2/1/0 |  |
| X680-22m | BIT STRING distinguishes leading and trailing bits | accept | accept:MET | COVERED | 1/0/0 |  |
| X680-22n | Named bits do not restrict the BIT STRING value set | accept | accept:MET | COVERED | 1/0/0 |  |
| X680-25t | OPTIONAL and DEFAULT components may be omitted | accept | accept:MET | COVERED | 10/2/0 |  |
| X680-28e | SET OF permits repeated component values | accept | accept:MET | COVERED | 1/1/0 |  |
| X680-29 | CHOICE values carry the selected alternative tag | accept, reject | accept:MET, reject:MET | COVERED | 12/6/0 |  |
| X680-31i | A prefixed type changes tags without changing values | accept | accept:MET | COVERED | 2/2/0 |  |
| X680-31j | Prefixed types are tagged or encoding-prefixed | accept, reject | accept:MET, reject:MET | COVERED | 3/1/0 |  |
| X680-31k | Encoding prefixes do not change abstract values | accept | accept:MET | COVERED | 1/0/0 |  |
| X680-40b | Restricted string tags come from their type definitions | accept, reject | accept:MET, reject:MET | COVERED | 7/7/0 |  |
| X680-46b | GeneralizedTime is universal 24 over restricted Visible... | accept, reject | accept:MET, reject:MET | COVERED | 2/0/0 |  |
| X680-47b | UTCTime is universal 23 over restricted VisibleString | accept, reject | accept:MET, reject:MET | COVERED | 2/0/0 |  |
| X680-8 | Tags pair a class with a nonnegative number | accept, reject | accept:MET, reject:MET | COVERED | 3/1/0 |  |
| X680-18 | BOOLEAN has universal tag 1 | accept | accept:MET | COVERED | 1/0/0 |  |
| X680-19 | INTEGER has universal tag 2 | accept | accept:MET | COVERED | 2/0/0 |  |
| X680-20 | ENUMERATED has universal tag 10 | accept | accept:MET | COVERED | 1/0/0 |  |
| X680-22 | BIT STRING has universal tag 3 | accept, reject | accept:MET, reject:MET | COVERED | 9/0/0 |  |
| X680-23 | OCTET STRING has universal tag 4 | accept, reject | accept:MET, reject:MET | COVERED | 5/4/0 |  |
| X680-24 | NULL has universal tag 5 | accept | accept:MET | COVERED | 1/0/0 |  |
| X680-25 | SEQUENCE has universal tag 16 | accept, reject | accept:MET, reject:MET | COVERED | 5/2/0 |  |
| X680-26 | SEQUENCE OF has universal tag 16 | accept, reject | accept:MET, reject:MET | COVERED | 2/0/0 |  |
| X680-28 | SET OF has universal tag 17 | accept, reject | accept:MET, reject:MET | COVERED | 6/4/0 |  |
| X680-31.2 | Tagged types replace the tag class and number | accept, reject | accept:MET, reject:MET | COVERED | 5/2/0 |  |
| X680-32 | OBJECT IDENTIFIER has universal tag 6 | accept | accept:MET | COVERED | 1/0/0 |  |
| X680-41.1 | Restricted string table assigns tags and repertoires | accept, reject | accept:MET, reject:MET | COVERED | 15/20/0 |  |
| X680-41.2 | NumericString permits only digits and space | accept, reject | accept:MET, reject:MET | COVERED | 5/5/0 |  |
| X680-41.4 | PrintableString has its listed 74-character repertoire | accept, reject | accept:MET, reject:MET | COVERED | 7/4/0 |  |
| X680-46.2 | GeneralizedTime combines a date with local or UTC time | accept, reject | accept:MET, reject:MET | COVERED | 7/3/0 |  |
| X680-46.3 | GeneralizedTime uses universal tag 24 | accept, reject | accept:MET, reject:MET | COVERED | 5/0/0 |  |
| X680-47.2 | UTCTime represents date time and an optional UTC offset | accept, reject | accept:MET, reject:MET | COVERED | 5/0/0 |  |
| X680-47.3 | UTCTime uses universal tag 23 | accept, reject | accept:MET, reject:MET | COVERED | 5/0/0 |  |

### STD source X501

| id | title | needs | role status | status | test/kani/lean | known gap |
|---|---|---|---|---|---|---|
| X501-9.2-d | Name syntax is an ordered RDN sequence | accept, reject | accept:MET, reject:MET | COVERED | 5/4/0 |  |
| X501-9.2-e | Name selects the RDNSequence alternative | accept, reject | accept:MET, reject:MET | COVERED | 4/4/0 |  |
| X501-9.2-f | RDNSequence is a sequence of RDNs | accept, reject | accept:MET, reject:MET | COVERED | 5/4/0 |  |
| X501-9.2-g | DistinguishedName aliases RDNSequence | accept, reject | accept:MET, reject:MET | COVERED | 4/4/0 |  |
| X501-9.3-d | RDN is a nonempty set of ATVs | accept, reject | accept:MET, reject:MET | COVERED | 7/5/0 |  |
| X501-9.3-e | ATV contains type and value fields | accept, reject | accept:MET, reject:MET | COVERED | 10/9/0 |  |
| X501-9.3-g | An RDN cannot repeat an attribute type | accept, reject | accept:MET, reject:MET | COVERED | 7/0/0 |  |

### STD source RFC8017

| id | title | needs | role status | status | test/kani/lean | known gap |
|---|---|---|---|---|---|---|
| RFC8017-A.1.1 | RSAPublicKey contains modulus and exponent | accept, reject | accept:MET, reject:MET | COVERED | 16/1/0 |  |
| RFC8017-A.1.1-a | RSA public keys use RSAPublicKey | accept, reject | accept:MET, reject:MET | COVERED | 5/1/0 |  |
| RFC8017-A.1.2 | RSAPrivateKey carries version and key components | accept, reject | accept:MET, reject:MET | COVERED | 15/9/0 |  |
| RFC8017-A.1.2-a | Two-prime keys use version zero | accept, reject | accept:MET, reject:MET | COVERED | 3/3/0 |  |
| RFC8017-A.1.2-b | Multi-prime keys use version one | accept, reject | accept:MET, reject:MET | COVERED | 3/2/0 |  |
| RFC8017-A.1.2-c | Version matches other-prime presence | accept, reject | accept:MET, reject:MET | COVERED | 6/3/0 |  |
| RFC8017-A.1.2-d | Version zero omits other primes | accept, reject | accept:MET, reject:MET | COVERED | 3/1/0 |  |
| RFC8017-A.1.2-e | Version one carries at least one other prime | accept, reject | accept:MET, reject:MET | COVERED | 3/1/0 |  |
| RFC8017-A.1.2-f | OtherPrimeInfos is a nonempty sequence | accept, reject | accept:MET, reject:MET | COVERED | 6/6/0 |  |
| RFC8017-A.1.2-g | OtherPrimeInfo contains three integers | accept, reject | accept:MET, reject:MET | COVERED | 6/6/0 |  |

### STD source RFC5915

| id | title | needs | role status | status | test/kani/lean | known gap |
|---|---|---|---|---|---|---|
| RFC5915-3 | EC private keys use ECPrivateKey | accept, reject | accept:MET, reject:MET | COVERED | 8/1/0 |  |
| RFC5915-3-a | ECPrivateKey carries required and optional fields | accept, reject | accept:MET, reject:MET | COVERED | 29/1/0 |  |
| RFC5915-3-b | EC private key version equals one | accept, reject | accept:MET, reject:MET | COVERED | 7/1/0 |  |

### STD source RFC5208

| id | title | needs | role status | status | test/kani/lean | known gap |
|---|---|---|---|---|---|---|
| RFC5208-5 | Private keys use PrivateKeyInfo | accept, reject | accept:MET, reject:MET | COVERED | 5/1/0 |  |
| RFC5208-5-a | PrivateKeyInfo has four ordered fields | accept, reject | accept:MET, reject:MET | COVERED | 17/1/0 |  |
| RFC5208-5-b | PrivateKeyInfo version equals zero | accept, reject | accept:MET, reject:MET | COVERED | 7/1/0 |  |
| RFC5208-6 | Encrypted keys use EncryptedPrivateKeyInfo | accept, reject | accept:MET, reject:MET | COVERED | 4/1/0 |  |
| RFC5208-6-a | EncryptedPrivateKeyInfo carries algorithm and ciphertext | accept, reject | accept:MET, reject:MET | COVERED | 8/1/0 |  |

### STD source RFC5958

| id | title | needs | role status | status | test/kani/lean | known gap |
|---|---|---|---|---|---|---|
| RFC5958-3 | Encrypted keys use EncryptedPrivateKeyInfo | accept, reject | accept:MET, reject:MET | COVERED | 4/1/0 |  |
| RFC5958-3-a | EncryptedPrivateKeyInfo carries algorithm and ciphertext | accept, reject | accept:MET, reject:MET | COVERED | 8/1/0 |  |

### STD source RFC3279

| id | title | needs | role status | status | test/kani/lean | known gap |
|---|---|---|---|---|---|---|
| RFC3279-2.2.3 | ECDSA signatures contain two integers | accept, reject | accept:MET, reject:MET | COVERED | 17/1/0 |  |
| RFC3279-2.2.3-c | ECDSA values use the signature structure | accept, reject | accept:MET, reject:MET | COVERED | 17/1/0 |  |
| RFC3279-2.3.1 | RSA public keys use RSAPublicKey | accept, reject | accept:MET, reject:MET | COVERED | 5/1/0 |  |
| RFC3279-2.3.1-b | RSAPublicKey contains modulus and exponent | accept, reject | accept:MET, reject:MET | COVERED | 16/1/0 |  |
| RFC3279-2.2.2 | A DSA signature value contains two INTEGER fields | accept, reject | accept:MET, reject:MET | COVERED | 2/0/0 |  |

### STD source RFC5480

| id | title | needs | role status | status | test/kani/lean | known gap |
|---|---|---|---|---|---|---|
| RFC5480-2 | EC SubjectPublicKeyInfo has two fields | accept, reject | accept:MET, reject:MET | COVERED | 12/1/0 |  |
| RFC5480-2-a | AlgorithmIdentifier has OID and optional parameters | accept, reject | accept:MET, reject:MET | COVERED | 14/1/0 |  |

### STD source RFC8410

| id | title | needs | role status | status | test/kani/lean | known gap |
|---|---|---|---|---|---|---|
| RFC8410-3-a | AlgorithmIdentifier contains OID and optional parameters | accept, reject | accept:MET, reject:MET | COVERED | 14/1/0 |  |
| RFC8410-4 | Safe-curve SPKI has algorithm and key bits | accept, reject | accept:MET, reject:MET | COVERED | 11/1/0 |  |
| RFC8410-6 | Certificate signature has three fields | accept, reject | accept:MET, reject:MET | COVERED | 10/0/0 |  |

### STD source RFC3629

| id | title | needs | role status | status | test/kani/lean | known gap |
|---|---|---|---|---|---|---|
| RFC3629-3 | UTF-8 uses one through four octets | accept, reject | accept:MET, reject:MET | COVERED | 11/4/0 |  |
| RFC3629-3-a | Each scalar has one valid encoding | accept, reject | accept:MET, reject:MET | COVERED | 12/4/0 |  |
| RFC3629-3-b | UTF-8 excludes surrogate code points | accept, reject | accept:MET, reject:MET | COVERED | 3/4/0 |  |
| RFC3629-3-c | Decoders reject invalid UTF-8 sequences | accept, reject | accept:MET, reject:MET | COVERED | 10/5/0 |  |
| RFC3629-4 | UTF-8 byte strings match the ABNF | accept, reject | accept:MET, reject:MET | COVERED | 19/4/0 |  |

## SAFE: Safety contracts

| id | title | needs | role status | status | test/kani/lean | known gap |
|---|---|---|---|---|---|---|
| SAFE-unsafe-1 | Library code contains no unsafe Rust | review | review:REVIEW | REVIEW | 0/0/0 |  |
| SAFE-panic-framing-1 | Framing entry points never panic on any input | prove | prove:MET | COVERED | 0/4/19 |  |
| SAFE-panic-content-1 | Content codecs never panic on any input | prove | prove:MET | COVERED | 0/9/4 |  |
| SAFE-panic-collections-1 | Collection codecs never panic on any input | prove | prove:MET | COVERED | 0/3/2 |  |
| SAFE-panic-keys-1 | Key-container parsers never panic on any input | prove | prove:MET | COVERED | 0/14/0 |  |
| SAFE-panic-x509-1 | X.509 parsers never panic on any input | prove | prove:MET | COVERED | 0/9/0 |  |
| SAFE-panic-profile-1 | Profile validation never panics on any value | prove | prove:MET | COVERED | 0/5/0 |  |
| SAFE-termination-1 | Identifier decoding terminates for arbitrary input length | prove | prove:MET | COVERED | 0/1/12 |  |
| SAFE-termination-2 | TLV and sequence walks terminate | prove | prove:MET | COVERED | 0/3/6 |  |
| SAFE-overread-1 | Accepted TLV decoding never reads beyond input | prove | prove:MET | COVERED | 1/2/2 |  |
| SAFE-overread-2 | Sequence child walking never overreads | prove | prove:MET | COVERED | 1/1/3 |  |
| SAFE-overread-3 | SET OF child walking never overreads | prove | prove:MET | COVERED | 0/2/0 |  |
| SAFE-resource-1 | Decode paths allocate no heap memory | gate | gate:MET | COVERED | 0/0/0 |  |
| SAFE-resource-2 | Composition depth is statically bounded | gate | gate:MET | COVERED | 0/0/0 |  |

## CODEC: Codec laws

| id | title | needs | role status | status | test/kani/lean | known gap |
|---|---|---|---|---|---|---|
| CODEC-tag-decode-encode | tag decode after encode preserves values | accept | accept:MET | COVERED | 3/1/0 |  |
| CODEC-tag-encode-decode | tag re-encoding preserves accepted bytes | accept | accept:MET | COVERED | 1/1/0 |  |
| CODEC-tag-unique | tag accepted values have canonical encodings | reject | reject:MET | COVERED | 1/1/0 |  |
| CODEC-tag-reject-nonder | tag rejects promised non-DER variants | reject | reject:MET | COVERED | 4/2/3 |  |
| CODEC-length-decode-encode | length decode after encode preserves values | accept | accept:MET | COVERED | 3/1/0 |  |
| CODEC-length-encode-decode | length re-encoding preserves accepted bytes | accept | accept:MET | COVERED | 1/1/1 |  |
| CODEC-length-unique | length accepted values have canonical encodings | reject | reject:MET | COVERED | 1/1/1 |  |
| CODEC-length-reject-nonder | length rejects promised non-DER variants | reject | reject:MET | COVERED | 5/3/4 |  |
| CODEC-tlv-decode-encode | tlv decode after encode preserves values | accept | accept:MET | COVERED | 2/1/0 |  |
| CODEC-tlv-encode-decode | tlv re-encoding preserves accepted bytes | accept | accept:MET | COVERED | 1/0/0 |  |
| CODEC-tlv-unique | tlv accepted values have canonical encodings | reject | reject:MET | COVERED | 1/0/0 |  |
| CODEC-tlv-reject-nonder | tlv rejects promised non-DER variants | reject | reject:MET | COVERED | 2/0/0 |  |
| CODEC-boolean-decode-encode | boolean decode after encode preserves values | accept | accept:MET | COVERED | 1/1/0 |  |
| CODEC-boolean-encode-decode | boolean re-encoding preserves accepted bytes | accept | accept:MET | COVERED | 1/1/0 |  |
| CODEC-boolean-unique | boolean accepted values have canonical encodings | reject | reject:MET | COVERED | 1/1/0 |  |
| CODEC-boolean-reject-nonder | boolean rejects promised non-DER variants | reject | reject:MET | COVERED | 3/1/0 |  |
| CODEC-integer-decode-encode | integer decode after encode preserves values | accept | accept:MET | COVERED | 1/1/0 |  |
| CODEC-integer-encode-decode | integer re-encoding preserves accepted bytes | accept | accept:MET | COVERED | 1/1/0 |  |
| CODEC-integer-unique | integer accepted values have canonical encodings | reject | reject:MET | COVERED | 1/1/0 |  |
| CODEC-integer-reject-nonder | integer rejects promised non-DER variants | reject | reject:MET | COVERED | 3/2/0 |  |
| CODEC-big-integer-decode-encode | big-integer decode after encode preserves values | accept | accept:MET | COVERED | 4/1/0 |  |
| CODEC-big-integer-encode-decode | big-integer re-encoding preserves accepted bytes | accept | accept:MET | COVERED | 1/1/0 |  |
| CODEC-big-integer-unique | big-integer accepted values have canonical encodings | reject | reject:MET | COVERED | 1/2/1 |  |
| CODEC-big-integer-reject-nonder | big-integer rejects promised non-DER variants | reject | reject:MET | COVERED | 5/5/1 |  |
| CODEC-bit-string-decode-encode | bit-string decode after encode preserves values | accept | accept:MET | COVERED | 1/1/0 |  |
| CODEC-bit-string-encode-decode | bit-string re-encoding preserves accepted bytes | accept | accept:MET | COVERED | 1/1/0 |  |
| CODEC-bit-string-unique | bit-string accepted values have canonical encodings | reject | reject:MET | COVERED | 1/2/0 |  |
| CODEC-bit-string-reject-nonder | bit-string rejects promised non-DER variants | reject | reject:MET | COVERED | 2/3/0 |  |
| CODEC-null-unique | null accepted values have canonical encodings | reject | reject:MET | COVERED | 1/1/0 |  |
| CODEC-null-reject-nonder | null rejects promised non-DER variants | reject | reject:MET | COVERED | 1/0/0 |  |
| CODEC-oid-unique | oid accepted values have canonical encodings | reject | reject:MET | COVERED | 1/0/1 |  |
| CODEC-oid-reject-nonder | oid rejects promised non-DER variants | reject | reject:MET | COVERED | 2/2/1 |  |
| CODEC-enumerated-decode-encode | enumerated decode after encode preserves values | accept | accept:MET | COVERED | 1/1/0 |  |
| CODEC-enumerated-encode-decode | enumerated re-encoding preserves accepted bytes | accept | accept:MET | COVERED | 1/0/0 |  |
| CODEC-enumerated-unique | enumerated accepted values have canonical encodings | reject | reject:MET | COVERED | 1/0/0 |  |
| CODEC-enumerated-reject-nonder | enumerated rejects promised non-DER variants | reject | reject:MET | COVERED | 2/0/0 |  |
| CODEC-octet-string-decode-encode | octet-string decode after encode preserves values | accept | accept:MET | COVERED | 2/1/0 |  |
| CODEC-octet-string-encode-decode | octet-string re-encoding preserves accepted bytes | accept | accept:MET | COVERED | 1/0/0 |  |
| CODEC-octet-string-unique | octet-string accepted values have canonical encodings | reject | reject:MET | COVERED | 1/0/0 |  |
| CODEC-octet-string-reject-nonder | octet-string rejects promised non-DER variants | reject | reject:MET | COVERED | 3/1/0 |  |
| CODEC-utf8-string-decode-encode | utf8-string decode after encode preserves values | accept | accept:MET | COVERED | 2/1/0 |  |
| CODEC-utf8-string-encode-decode | utf8-string re-encoding preserves accepted bytes | accept | accept:MET | COVERED | 1/0/0 |  |
| CODEC-utf8-string-unique | utf8-string accepted values have canonical encodings | reject | reject:MET | COVERED | 1/3/0 |  |
| CODEC-utf8-string-reject-nonder | utf8-string rejects promised non-DER variants | reject | reject:MET | COVERED | 3/0/0 |  |
| CODEC-restricted-string-decode-encode | restricted-string decode after encode preserves values | accept | accept:MET | COVERED | 4/4/0 |  |
| CODEC-restricted-string-encode-decode | restricted-string re-encoding preserves accepted bytes | accept | accept:MET | COVERED | 1/0/0 |  |
| CODEC-restricted-string-unique | restricted-string accepted values have canonical encodings | reject | reject:MET | COVERED | 1/0/0 |  |
| CODEC-restricted-string-reject-nonder | restricted-string rejects promised non-DER variants | reject | reject:MET | COVERED | 3/0/0 |  |
| CODEC-generalized-time-decode-encode | generalized-time decode after encode preserves values | accept | accept:MET | COVERED | 3/1/0 |  |
| CODEC-generalized-time-encode-decode | generalized-time re-encoding preserves accepted bytes | accept | accept:MET | COVERED | 1/1/0 |  |
| CODEC-generalized-time-unique | generalized-time accepted values have canonical encodings | reject | reject:MET | COVERED | 1/1/0 |  |
| CODEC-generalized-time-reject-nonder | generalized-time rejects promised non-DER variants | reject | reject:MET | COVERED | 9/5/0 |  |
| CODEC-utc-time-decode-encode | utc-time decode after encode preserves values | accept | accept:MET | COVERED | 1/1/0 |  |
| CODEC-utc-time-encode-decode | utc-time re-encoding preserves accepted bytes | accept | accept:MET | COVERED | 1/1/0 |  |
| CODEC-utc-time-unique | utc-time accepted values have canonical encodings | reject | reject:MET | COVERED | 1/2/0 |  |
| CODEC-utc-time-reject-nonder | utc-time rejects promised non-DER variants | reject | reject:MET | COVERED | 5/3/0 |  |
| CODEC-sequence-decode-encode | sequence decode after encode preserves values | accept | accept:MET | COVERED | 1/1/0 |  |
| CODEC-sequence-encode-decode | sequence re-encoding preserves accepted bytes | accept | accept:MET | COVERED | 1/0/0 |  |
| CODEC-sequence-unique | sequence accepted values have canonical encodings | reject | reject:MET | COVERED | 1/0/0 |  |
| CODEC-sequence-reject-nonder | sequence rejects promised non-DER variants | reject | reject:MET | COVERED | 3/0/0 |  |
| CODEC-set-of-decode-encode | set-of decode after encode preserves values | accept | accept:MET | COVERED | 1/1/0 |  |
| CODEC-set-of-encode-decode | set-of re-encoding preserves accepted bytes | accept | accept:MET | COVERED | 1/0/0 |  |
| CODEC-set-of-unique | set-of accepted values have canonical encodings | reject | reject:MET | COVERED | 1/3/0 |  |
| CODEC-set-of-reject-nonder | set-of rejects promised non-DER variants | reject | reject:MET | COVERED | 6/6/0 |  |
| CODEC-context-tag-reject-nonder | context-tag rejects promised non-DER variants | reject | reject:MET | COVERED | 1/0/0 |  |
| CODEC-algorithm-identifier-reject-nonder | algorithm-identifier rejects promised non-DER variants | reject | reject:MET | COVERED | 2/0/0 |  |
| CODEC-spki-reject-nonder | spki rejects promised non-DER variants | reject | reject:MET | COVERED | 3/0/0 |  |
| CODEC-name-reject-nonder | name rejects promised non-DER variants | reject | reject:MET | COVERED | 2/1/0 |  |
| CODEC-validity-reject-nonder | validity rejects promised non-DER variants | reject | reject:MET | COVERED | 2/0/0 |  |
| CODEC-extension-reject-nonder | extension rejects promised non-DER variants | reject | reject:MET | COVERED | 3/1/0 |  |
| CODEC-extensions-reject-nonder | extensions rejects promised non-DER variants | reject | reject:MET | COVERED | 1/0/0 |  |
| CODEC-tbs-certificate-reject-nonder | tbs-certificate rejects promised non-DER variants | reject | reject:MET | COVERED | 1/0/0 |  |
| CODEC-certificate-reject-nonder | certificate rejects promised non-DER variants | reject | reject:MET | COVERED | 1/0/0 |  |
| CODEC-pkcs8-reject-nonder | pkcs8 rejects promised non-DER variants | reject | reject:MET | COVERED | 2/0/0 |  |
| CODEC-encrypted-pkcs8-reject-nonder | encrypted-pkcs8 rejects promised non-DER variants | reject | reject:MET | COVERED | 1/0/0 |  |
| CODEC-ec-private-key-reject-nonder | ec-private-key rejects promised non-DER variants | reject | reject:MET | COVERED | 4/0/0 |  |
| CODEC-ecdsa-sig-value-reject-nonder | ecdsa-sig-value rejects promised non-DER variants | reject | reject:MET | COVERED | 3/0/0 |  |
| CODEC-rsa-public-key-reject-nonder | rsa-public-key rejects promised non-DER variants | reject | reject:MET | COVERED | 3/0/0 |  |
| CODEC-rsa-private-key-reject-nonder | rsa-private-key rejects promised non-DER variants | reject | reject:MET | COVERED | 3/0/0 |  |

## PROF: Profile decisions

| id | title | needs | role status | status | test/kani/lean | known gap |
|---|---|---|---|---|---|---|
| PROF-bit-string-preserve-zero-bits | Generic bit strings preserve trailing zero bits | accept | accept:MET | COVERED | 1/0/0 |  |
| PROF-integer-i64-cap | Small INTEGER values are capped at i64 | accept, reject | accept:MET, reject:MET | COVERED | 3/1/0 |  |
| PROF-length-u32-cap | Decoded lengths are capped at u32 | accept, reject | accept:MET, reject:MET | COVERED | 2/1/1 |  |
| PROF-tag-u32-cap | Decoded tag numbers are capped at u32 | accept, reject | accept:MET, reject:MET | COVERED | 2/1/5 |  |
| PROF-lenient-trailing | Composable decoders return consumed length | accept | accept:MET | COVERED | 8/1/0 |  |
| PROF-sequence-framing-only | Sequence walking defers child content canonicality | accept | accept:MET | COVERED | 3/1/0 |  |
| PROF-time-no-leap-second | Time codecs reject leap-second value sixty | accept, reject | accept:MET, reject:MET | COVERED | 4/8/0 |  |
| PROF-time-field-ranges | Time codecs enforce individual field ranges | accept, reject | accept:MET, reject:MET | COVERED | 17/18/0 |  |
| PROF-explicit-context-only | Generic context tagging supports EXPLICIT only | accept, reject | accept:MET, reject:MET | COVERED | 3/2/0 |  |
| PROF-unique-identifiers-rejected | Deprecated certificate unique identifiers are rejected | accept, reject | accept:MET, reject:MET | COVERED | 3/0/0 |  |
| PROF-P-1 | Certificate signature algorithm fields match | accept, reject | accept:MET, reject:MET | COVERED | 5/2/0 |  |
| PROF-P-2 | Certificate extensions require version three | accept, reject | accept:MET, reject:MET | COVERED | 6/2/0 |  |
| PROF-P-3 | Validity encoding follows the year boundary | accept, reject | accept:MET, reject:MET | COVERED | 11/3/0 |  |
| PROF-P-4 | Profile violation precedence is stable | accept, reject | accept:MET, reject:MET | COVERED | 10/2/0 |  |
| PROF-P-11 | Validity GeneralizedTime omits fractional seconds | accept, reject | accept:MET, reject:MET | COVERED | 7/2/0 |  |
| PROF-P-12 | Certificate extensions do not repeat an extension ident... | accept, reject | accept:MET, reject:MET | COVERED | 5/0/0 |  |
| PROF-P-13 | Certificate issuer name is not empty | accept, reject | accept:MET, reject:MET | COVERED | 4/1/0 |  |
| PROF-P-14 | Issuer and subject RDNs do not repeat an attribute type | accept, reject | accept:MET, reject:MET | COVERED | 7/0/0 |  |
| PROF-strict-trailing | Strict entry points reject bytes after one complete object | accept, reject | accept:MET, reject:MET | COVERED | 33/7/0 |  |
| PROF-identifier-form-opt-in | Identifier-form validation is explicit and leaves unass... | accept, reject | accept:MET, reject:MET | COVERED | 5/2/0 |  |
| PROF-big-integer-comparison-only | Large INTEGER values remain minimal two-complement byte... | accept, reject | accept:MET, reject:MET | COVERED | 12/7/0 |  |

## API: Public API commitments

| id | title | needs | role status | status | test/kani/lean | known gap |
|---|---|---|---|---|---|---|
| API-stability-1 | Public API receives a final stability review | review | review:REVIEW | REVIEW | 0/0/0 |  |
| API-msrv-1 | Declared MSRV remains supported | review | review:REVIEW | REVIEW | 0/0/0 |  |
| API-bit-string-octet-aligned | Callers can require a byte-aligned BIT STRING payload | review | review:REVIEW | REVIEW | 2/2/0 |  |
| API-short-buffer-none | Slice encoders report insufficient output space with None | review | review:REVIEW | REVIEW | 8/10/0 |  |
| API-profile-error-non-exhaustive | Only ProfileError reserves future enum variants | review | review:REVIEW | REVIEW | 0/0/0 |  |
| API-tbs-signed-bytes-access | TBS parse results expose the exact bytes covered by a s... | review | review:REVIEW | REVIEW | 0/0/0 |  |

## Work list for S4

Every row that is not COVERED, grouped by its first listed module.
Each line says which test role is missing.

No rows. Every judged row is COVERED.

### Review-only rows (no test obligation)

- X690-10 [REVIEW]: DER combines basic encoding with clauses 10 and 11
- X690-8.1.1.4 [REVIEW]: Subtype constraints and extension markers do not alter...
- SAFE-unsafe-1 [REVIEW]: Library code contains no unsafe Rust
- API-stability-1 [REVIEW]: Public API receives a final stability review
- API-msrv-1 [REVIEW]: Declared MSRV remains supported
- API-bit-string-octet-aligned [REVIEW]: Callers can require a byte-aligned BIT STRING payload
- API-short-buffer-none [REVIEW]: Slice encoders report insufficient output space with None
- API-profile-error-non-exhaustive [REVIEW]: Only ProfileError reserves future enum variants
- API-tbs-signed-bytes-access [REVIEW]: TBS parse results expose the exact bytes covered by a s...
