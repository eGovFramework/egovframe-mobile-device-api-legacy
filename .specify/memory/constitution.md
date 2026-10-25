# egovframe-mobile-device-api-legacy Constitution

## Core Principles

### I. Preserve the published domain and compatibility

This repository provides legacy eGovFrame hybrid Android/iOS Cordova Device API samples with a Spring MVC web-guide server. Changes MUST preserve legacy bridge callbacks, server payloads, version-specific sample setup, and each platform network-policy boundary unless a separately
reviewed upstream contract change explicitly requires otherwise. Use the repository evidence
in [project context](project-card.md) to identify the affected boundary before editing.
Example applications and guides are maintained as examples, not silently redesigned as products.

### II. Establish meaning before implementation

Before a functional change, complete a domain card from
[the model card template](../templates/model-card-template.md) in `.specify/model-cards/`.
Distinguish published contracts, upstream requests, observed behavior, and unverified inference.
Use a specification for new behavior or `/speckit.bug.assess` for a suspected defect when
warranted, then make a scoped plan before implementation. Unresolved new product policy MUST
remain an explicit blocker; a small corrective fix MUST retain the existing contract.

### III. Keep changes bounded and reviewable

A change MUST address one evidenced concern and preserve unrelated user work. Do not combine
Spec Kit adoption, dependency upgrades, formatting, and application fixes in one submission.
Read current contribution instructions and open upstream issues/PRs before proposing a fix.
Do not manufacture an application-wide specification or an empty decision record for adoption.

### IV. Verify what actually changed

Use the commands and environmental constraints in [project context](project-card.md).
A behavioral fix MUST have a focused reproducer or regression check where feasible; run the
relevant check after implementation and record its command, environment, and observed result.
Static inspection, a scaffold smoke, and a skipped or undiscovered test MUST NOT be described
as passing application tests. Report unavailable infrastructure and untested device/runtime
behavior explicitly. Full builds are not required merely to install these workflow files.

### V. Protect source and submission boundaries

Never commit credentials, private logs, real personal data, local authentication state, or
machine-specific settings. Use synthetic examples and preserve existing license notices.
Keep `.specify/`, `.omp/commands/`, model cards, plans, and work reports on the fork work branch.
Prepare upstream contributions from the fetched upstream default SHA in a separate submission
workspace; never merge work or cherry-pick the adoption commit into an upstream submission.
Preserve existing submission branches and PRs. No force pushes or automatic merges.

## Repository Evidence and Constraints

The [project context card](project-card.md) records the README, manifests, and available
verification evidence for this repository. It is a navigation aid, not proof that those checks
have run. Preserve each module's declared toolchain and deployment assumptions; environment
or dependency changes require separate evidence and review. This constitution governs fork
maintenance and does not claim endorsement or adoption by upstream maintainers.

## Development Workflow and Review Gates

1. Read project context and current upstream guidance; identify the exact baseline and scope.
2. Complete a domain card, then a specification or bug assessment when needed, then a plan.
3. Implement only the approved concern and its focused regression coverage.
4. Execute relevant verification; distinguish observed results from remaining limitations.
5. Inspect submission commits and changed paths against the recorded upstream baseline.
   Exclude work-only tooling and private information, and submit only a cohesive verified change.
   Do not remove files already present upstream just because their names resemble work artifacts.

For workflow use Spec Kit 1.2.3 with native OMP command Markdown in `.omp/commands/` and the
bundled bug workflow. Slash commands are agent instructions, not shell programs. Read them in
the active agent; do not change global model, provider, authentication, or billing settings.

## Governance

This is the initial fork-maintenance constitution. Amendments MUST state the reason, public
repository evidence, compatibility impact, and changed review obligations in a work-branch
review. Use semantic versions: major for incompatible principles, minor for new obligations,
patch for clarifications. Review each change against these principles and disclose unresolved
exceptions before submission; evidence in source and published contracts takes precedence over
an unsupported claim in a generated plan. Never edit generated Spec Kit commands to customize
policy; maintain policy here and repository facts in the linked context card.

**Version**: 1.0.0 | **Ratified**: 2026-10-26 | **Last Amended**: 2026-10-26
