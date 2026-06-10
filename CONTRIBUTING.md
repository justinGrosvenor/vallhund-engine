# Contributing

Thanks for looking under the hood. This repo is the open judgment core behind
Vallhund; contributions that sharpen detection, shrink the unknown pile, or
improve the honesty of claims are very welcome.

## Ground rules

- **License.** The project is AGPL-3.0-only. By contributing you agree your
  contribution is licensed under the same terms. There is no CLA.
- **The oracle is the contract.** `npm test` must pass, including
  `src/engine/oracle.test.ts`. If your change moves recall, precision, or the
  honesty ceiling, the PR must say so explicitly and update the fixtures
  deliberately. A red oracle is never a flake.
- **Pure means pure.** Nothing in `src/` may read credentials, talk to a
  database, or depend on hosted infrastructure. Network access is allowed only
  in clearly gated, credential-free checks (FCrDNS verification, the front-door
  scan, the public KEV catalog), and must be timeout-bounded and best-effort.
- **No silent claims.** A detector that cannot be exercised by a fixture does
  not merge. Coverage layers on findings must reflect what was actually
  observed.

## Good first contributions

- New user-agent signatures in `src/traffic/actors.ts` (AI agents change
  monthly; the registry is meant to grow).
- New sensitive-path or exfil-path patterns in `src/traffic/paths.ts`.
- ASN table entries in `src/enrich/asn.ts`.
- Remediation prompt packs in `src/remediation/remediation.ts`.

Each of the above has an adjacent `.test.ts`; add a case alongside your change.

## Workflow

```bash
npm install
npm test          # vitest, includes the golden oracle
npm run typecheck # strict tsc, no emit
npm run lint      # typescript-eslint strict + stylistic, type-checked
```

All three must be green. Tests live next to the code they lock
(`foo.ts` / `foo.test.ts`).
