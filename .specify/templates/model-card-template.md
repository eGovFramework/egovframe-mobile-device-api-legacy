# Domain model card: concept or feature name

Use this card before a specification or bug assessment. This describes a domain concept,
not a machine learning model. Follow [the constitution](../memory/constitution.md) and
[project context](../memory/project-card.md); link to those policies rather than repeating them.
Save the completed card as `.specify/model-cards/<concept>.md` on work only.

## One-sentence meaning

Define the concept, its users, and its observable boundary in one sentence.

## Why it is needed

Describe the concrete problem and who benefits; cite a public request or observed behavior.

## Existing models and vocabulary

Link the relevant public API, schema, screen, implementation, or upstream documentation.
Explain which terms and compatibility commitments are retained.

## Synthetic example data

Provide a small invented input and expected representation. Include a boundary case.
Use no real users, production records, secrets, or private project examples.

## Accepted and rejected behavior

| Scenario | Synthetic input | Expected result | Evidence |
| --- | --- | --- | --- |
| Successful use | Describe an ordinary valid input | Observable success | Public contract or observation |
| Refused use | Describe an invalid or out-of-scope input | Observable rejection or existing error | Public contract or observation |

## Non-goals and responsibility boundaries

State what this concept does not own, including integrations or policies delegated elsewhere.

## Rule sources and assumptions

For each rule identify its source and label it as published contract, upstream issue/request,
observed implementation, or unverified inference. Give a file path or public URL and revision
where possible. An issue is a request, not proof of agreed behavior. Separate current behavior
from intended behavior; do not convert an assumption into user agreement.

## Open questions

List unresolved questions, their effect, and the evidence needed to settle them. A missing
product-policy decision that changes existing behavior blocks that decision until resolved.

## Validation and next step

Name the focused check that could distinguish success from failure and its environment.
Link a specification or bug assessment when warranted, then the implementation plan.
Record results only after execution; keep cards and plans out of upstream submissions.
