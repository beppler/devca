# DevCA

## Overview

Manages Certificate Authorities and Server Certificates for development.

## Tech Stack

Go, Bash (for build scripts), GitHub Actions to generate releases.

## Basic instructions

1. Separation of Concerns — one kind of work per part (UI / domain / persistence / infra). Root principle.
2. Encapsulation / Information Hiding — small stable contract; hide internals.
3. High Cohesion + Loose Coupling — change-together lives together; independents talk narrow.
4. DRY — one authoritative representation of each piece of *knowledge* (not every similar line). Avoid over-DRY.
5. KISS — simplest design that works; complexity is the long-term tax.
6. Single Responsibility — one reason to change.
7. Depend on Abstractions — policy doesn’t depend on details; both depend on contracts.
8. YAGNI — no speculative features, frameworks, or “later” hooks.
9. Composition over Inheritance — assemble pieces; don’t grow fragile hierarchies.
10. Open/Closed (with discipline) — extend at stable boundaries; only where change showed up twice.
11. Law of Demeter · fail fast / illegal states unrepresentable · optimize for deletion · Unix do-one-thing + compose.
12. Don't touch anything outside this task, and don't break anything that already works.
