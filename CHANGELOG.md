# Changelog

## 1.6.0 (2026-11-07)

- `export_token_file`: a bearer token that opens `GET /api/export`, the model
  `--json` prints, to read-only aggregators such as Cairn Map.

## 1.5.0 (2026-11-07)

- Updates view: which Renovate update types merge by themselves, from the
  repository's Renovate config (`renovate_file`); the server edits it like
  any change (diff, commit, pull request): tick the types of the rule
  `Cairn IaC: automerge` (`automerge` + `platformAutomerge`), keep a
  dependency out with its reason, allow it again. Rules with automerge off
  are listed, flagged when placed before the automerge rule.
- With `forge_api`, `forge_repo`, `forge_token_file` (Forgejo/Gitea), the
  open Renovate pull requests: updates, CI state, automerge as Renovate set
  it.
- Roles included by other roles (tasks, blocks, `meta` dependencies) now
  count for the play's hosts: machine roles, required roles in Drift, the
  JSON export.

## 1.4.0 (2026-11-07)

- Settings that CI must share with the page live in the repository:
  `repo_settings` (default `.cairn-iac.json`, a JSON file at the root of
  the IaC repository). Its `accepted_findings`, `vcpu_ratio`,
  `node_capacity` and `required_roles` win over the config and the
  server's settings; Settings says which fields the file sets. A value of
  the wrong type is left out, and an unusable file is a drift warning.
- With that file, Accept / Stop accepting edits it like any other change:
  diff, commit, and in `agit` or `branch` mode a pull request, so the
  acceptance counts once merged. Without it (`repo_settings` empty), the
  server's settings keep them, as in 1.3.0.
- README: running `--check` in CI (Forgejo Actions example).

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
