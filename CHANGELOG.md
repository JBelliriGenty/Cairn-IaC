# Changelog

## 1.3.0 (2026-11-07)

- Accept a drift finding (server): a reason is required; the finding stays
  listed, greyed, with its reason, and no longer counts in the menu badge,
  the overview or `--check` (printed as `ok … (accepted: …)`). Stored in
  `accepted_findings` (`{finding id: reason}`), also readable from the
  config file for CI. Each finding now has a stable `id`
  (`kind:machine[:detail]`) that survives a value change.
- `vcpu_ratio` (Settings → Node capacity, default 1): vCPU a node may give
  per declared core, since CPU time is shared; memory and disk stay 1 for 1.

## 1.2.0 (2026-11-07)

- `GET /api/summary` for dashboards such as Homepage, opened by a bearer
  token (`summary_token_file`): machines, firewalls, roles, drift warnings
  and notes, commit, sync error.

## 1.1.1 (2026-11-06)

- Static page: the server-only "New machine" and "Settings" entries are
  hidden again (they showed and led back to the overview).

## 1.1.0 (2026-11-05)

- New machine (server): copy a model's Tofu block, its guest firewall (with
  or without its rules) and its inventory groups into a new machine, plus a
  role if asked, in one commit; checked values, files parsed again, the
  `tofu plan -target` / `apply` commands shown in the preview.
- An edit can now change several files in one commit; the review shows the
  diff of each.
- Machine history (server): the latest commits touching a machine; in
  `agit` mode the pull request description says who proposed it; a role
  goes into the play that already targets exactly that host.
- Node capacity on the machine map (`node_capacity`, memory in GiB, disk
  shown in TB from 1024 GB), a search field (`/`) and the JSON export
  (`--json`, "Download JSON").
- Flows view (who may talk to whom, from the guest firewall rules) and the
  half-open flow finding.
- Drift view and `--check` (exit 1 on a warning, `--json`).
- A Tofu `vm_id` given by a variable no longer stops the page.

## 1.0.0 (2026-11-05)

First release: the page, the server mode (edits, diff, commit and push,
`push` / `branch` / `agit` modes, Settings), the image on ghcr.io.
