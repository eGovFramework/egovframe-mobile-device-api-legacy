# egovframe-mobile-device-api-legacy: project context

## Role and maintenance boundary

Legacy eGovFrame hybrid Android/iOS Cordova Device API samples with a Spring MVC web-guide server. Preserve legacy bridge callbacks, server payloads, version-specific sample setup, and each platform network-policy boundary.
This card reflects source inspection at adoption; it does not certify runtime behavior.

## Public entry points and evidence

- `README.md`: eGovFrame 4.3.x-and-earlier scope, Android Eclipse/Studio and iOS samples, Java 8 server, local-learning-only use, and migration pointer to the newer repository.
- `web-guide/pom.xml`: WAR packaging, Spring 4.3.25.RELEASE, Java 8 source/target, and Surefire `skipTests=true`.
- `android-studio/DeviceAPIGuide_SampleTemplate_AndroidStudio/build.gradle` and `app/build.gradle`: Android Gradle plugin 3.0.1, legacy SDK settings, Cordova library, and Java 8 compile options.
- `ios/` contains separate Xcode/Cordova projects; these are not one unified mobile build.

## Build and verification entry points

The server packaging entry point is `mvn -f web-guide/pom.xml package`; its Surefire
configuration skips tests, so a successful package is not a test result. Before a future
server fix, establish a focused runnable regression check and confirm that it is discovered.
For Android open the specific sample in its compatible Android Studio/SDK environment and
use that sample build; iOS needs its matching Xcode project and device/simulator. There is
no verified repository-wide mobile test command. Do not invoke deployment or push services
merely to adopt workflow files.

## Environment and evidence limits

README explicitly limits these examples to local development and learning. Preserve that
warning and its HTTPS/network-policy distinctions; do not claim production suitability.
Old Cordova, Gradle repositories, native SDKs, DB setup, and external push services constrain
reproduction. Never read or copy potential service-account keys into cards or reports.
Public dependency/cache issues are follow-up requests and are unchanged by adoption.
No application build, test suite, formatter, device test, or external service was run for this
workflow-only adoption. A Spec Kit CLI/status and isolated scaffold smoke validate the tooling
only. No CodeGraph index was present in the adoption workspace; targeted file listing and
exact text inspection supplied the evidence, without installing an indexer.

## Upstream and submission baseline

Upstream: [eGovFramework/egovframe-mobile-device-api-legacy](https://github.com/eGovFramework/egovframe-mobile-device-api-legacy). Fetch the actual upstream default branch
and record its exact SHA before preparing `upstream-submit`; do not infer the baseline from
fork work. Preserve an existing submission branch or open PR. Adoption changes are pushed
only to fork `work`; an absent `upstream-submit` is created from the fetched upstream SHA
without adoption commits, as a separate submission baseline.
The [constitution](constitution.md) is the policy source for domain cards, verification, and
work-only artifact isolation. Native OMP commands are in `.omp/commands/`; the bundled bug
workflow provides assess, fix, and test stages. No application fix or PR is part of
this adoption.
