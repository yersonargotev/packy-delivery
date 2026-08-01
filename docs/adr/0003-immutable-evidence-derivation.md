# ADR 0003: Derive evidence only through immutable compatibility proof

## Status

Accepted

## Context

A candidate-changing repair creates a new Delivery Candidate. Packy Delivery
currently obtains the complete review and validation set again, even when a
small derived delta leaves part of the prior evidence unchanged. Retaining that
evidence can reduce ceremony, but copying it onto the new candidate would erase
the facts that made it authoritative.

A tree identifies file content, not delivery meaning. Equal trees can belong to
different commits, Delivery Authorities, acceptance matrices, risk profiles,
review generations, validator registrations, sandboxes, instrumentation, or
workspace observations. Tree equality is therefore necessary for reusing an
execution result across different commits, but never sufficient for review or
validation reuse.

This decision defines the contract that later implementation may admit. It does
not enable cross-candidate evidence reuse in `Advance`.

## Decision

### Parent and derived candidate identity

An evidence derivation names exactly one parent candidate and one distinct
derived candidate. Each identity contains the candidate ID, base commit, exact
commit, exact tree, review generation, risk profile, required Standards and
Spec axes, and sensitive boundaries. The assessment separately binds both
candidates to the canonical run schema, Delivery Run ID, and Delivery Authority
digest. The derived candidate must be a distinct candidate and commit; equality
of its tree with the parent only establishes content compatibility for later
validation evaluation.

Schema `packy.evidence-impact-assessment/v1` is the canonical typed impact
assessment owned by `internal/deliveryevidence`. Its identity is the SHA-256
digest of its canonical JSON with the
identity field empty. Set-valued axes, boundaries, obligations, and change
classes are ordered before the digest is calculated. A stale digest,
non-canonical ordering, duplicate or missing identity, unknown enum, or unknown
schema fails closed.

The assessment binds:

- its author kind and identity;
- parent and derived authority, run, candidate, commit, and tree identities;
- parent and derived review generations, profiles, required axes, and sensitive
  boundaries;
- parent and derived canonical acceptance-set digests and obligation counts,
  plus every obligation by criterion, evidence kind, owning phase,
  disposition, and rationale;
- every changed scope class and any exact affected boundary; and
- whether the assessment is complete.

Partial obligation coverage, an incomplete assessment, or ambiguity has the
same effect as a protected change: all evidence required by the resulting
profile is fresh.

### Authorship and independent confirmation

An authorized human maintainer may author semantic impact judgment. A
registered deterministic policy may author only when its immutable
registration digest is included; an unregistered tool, model transcript, log,
or free-form execution has no authoring authority.

Authorization is admitted through a trusted Delivery Authority resolver, not
from the identity strings in the assessment. That resolver must admit the
author and confirmer and independently establish that they are different
principals. For registered policies it resolves the immutable registration;
for humans it resolves the authenticated maintainer/reviewer principals. A
caller-authored alias never establishes authorization or independence.

Any retained evidence requires an independent confirmation using
`packy.evidence-impact-confirmation/v1`. The response binds the exact assessment
digest and parent and derived candidate IDs, identifies its confirmer, records
acceptance or rejection and a rationale, and has its own canonical digest. The
confirmer must not be the assessment author. Only one completed, accepted,
non-stale response may admit the assessment. Rejection, duplication,
self-confirmation, partial response, or mismatched identity requires the fresh
evidence path.

### Mandatory fresh evidence

The evaluator may identify prior evidence as *retainable* for later tickets; it
does not itself copy, relabel, persist, or satisfy that evidence. A non-behavioral
complete delta may retain explicitly unaffected review and specialist evidence,
but still requires a Standards delta review and independent impact
confirmation.

The following changes always require fresh evidence:

| Change | Mandatory fresh evidence |
| --- | --- |
| Delivery Authority or authority digest | complete Standards, Spec, all profile-required specialist reviews, boundary proof, and exhaustive validation |
| Behavior, public contract, scope, architecture, or security posture | complete Standards, Spec, all profile-required specialist reviews, boundary proof, and exhaustive validation |
| Acceptance meaning, criterion identity, evidence kind, owning phase, or obligation disposition | complete Spec proof for the affected matrix and exhaustive validation; Standards remains subject to its delta |
| Risk profile or required review set | complete reviews, specialists, boundary proof, and exhaustive validation for the resulting profile |
| Added, removed, or changed sensitive boundary | fresh specialist review and boundary proof for each affected boundary plus exhaustive validation |
| Validator, required command, sandbox root, instrumentation, expiry, or workspace state | fresh exhaustive validation and affected boundary proof |
| Incomplete, partial, contradictory, duplicated, stale, or ambiguous impact | complete reviews, specialists, boundary proof, and exhaustive validation for the resulting profile |

Review retention never supplies new semantic acceptance proof. Changed
Standards scope requires fresh Standards evidence; changed acceptance meaning
requires fresh criterion-specific Spec evidence. Boundary evidence remains
owned by its exact specialist and validation obligation.

### Validation compatibility tuple

Schema `packy.validation-compatibility-assessment/v1` evaluates one registered
validation artifact against one current obligation. The complete tuple binds:

- the accepted impact-assessment digest;
- its one admitted independent-confirmation digest;
- the registered validation-session schema, session ID, completion digest, and
  exactly one unambiguous completion;
- the exact parent and derived candidate, commit, and tree identities and their
  canonical derivation;
- the original and required obligation (`exhaustive` or one exact sensitive
  boundary);
- validator identity and digest, required command, matching source and required
  expiry, sandbox home and configuration roots, instrumentation set, and
  covered boundaries;
- clean source and current workspace observations; and
- completed successful execution.

The source must be a canonical registered validation session. Arbitrary logs,
reviewer command output, unregistered manual execution, and reconstructed
success prose are not canonical receipts. Compatibility evaluation resolves
the exact session and completion identities through the trusted canonical
validation-session registry and compares the complete registered artifact with
the claimed source tuple; a caller-controlled kind or schema string proves
nothing. An artifact can satisfy only the
exhaustive or boundary obligation it originally proved. Tree equality without
the accepted derivation and every other compatible tuple member is refused.

Expiry is evaluated against the trusted lifecycle clock. Any malformed or
expired timestamp, failed or interrupted execution, dirty workspace, stale
candidate, validator drift, command drift, sandbox drift, instrumentation
drift, boundary mismatch, different obligation, or ambiguous completion emits
a bounded typed invalidation and requires fresh validation.

### Replay, stale identity, and persistence

Exact replay of the same canonical assessment and confirmation is idempotent.
The same ID with different canonical content, or the same content under a
different claimed ID, is stale and rejected. A partially compatible assessment
may retain only obligations explicitly proven unaffected after confirmation;
every other obligation follows its mandatory fresh path. Ambiguity never
defaults to retention.

Later implementation must represent retained review and validation evidence as
new canonical derivation receipts linked to the parent receipt, assessment,
confirmation, and compatibility decision. It must not mutate, copy, or relabel
the parent receipt. Replay and crash recovery adopt one matching derived receipt
without duplication; conflicting receipts block.

This ticket adds standalone canonical JSON contracts only. It does not add
fields to `Candidate`, `runWire`, schema-v2 evidence bundles, compact reports,
or schema-v1 records. Tickets that persist derivation receipts must use additive
optional v2 fields so pre-feature v2 bytes remain readable. Absence means no
derivation authority; historical records never receive synthetic assessments.

Schema v1 remains readable only under its original semantics. A v1 run cannot
admit derivation evidence. It must finish through the legacy workflow or be
explicitly requalified as a new v2 run with new authority and candidate
identities.

### Gates that never derive

Evidence derivation never relaxes fresh authority acquisition, exact-HEAD CI,
explicit non-local authorization, push and pull-request identity, merge
eligibility, merge verification, issue closure, or cleanup. These gates always
observe the current derived candidate and current external state.

## Consequences

- Later review and validation reuse has one immutable, fail-closed vocabulary.
- Safe evidence can eventually reduce repeated work without changing its owner
  or meaning.
- Existing v1 and v2 runs and canonical JSON remain readable because this
  decision does not change persisted run layout.
- `Advance` continues to require the existing full evidence path until the
  follow-up implementation tickets admit canonical derivation receipts.
