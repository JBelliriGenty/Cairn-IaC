# Configuration reference

Everything Cairn IaC reads or writes, key by key. The [README](../README.md)
explains what the page shows; this page is what you edit.

| File | Who writes it | |
|---|---|---|
| `config.json` (`-c`) | you | where the repository is, the page, the server's access rules |
| token files (`summary_token_file`, `export_token_file`, `forge_token_file`) | you | one secret per file, never in the config |
| `.cairn-iac.json` (`repo_settings`), in the IaC repository | you, or the server's Accept button | the settings CI must see too |
| `renovate.json` (`renovate_file`), in the IaC repository | you, Renovate, or the Updates view | which updates merge by themselves |
| `<data_dir>/settings.json` | the server's Settings page | the page and repository settings, once the server runs |
| other files in `data_dir` | the server | deploy key, `known_hosts`, the clone |

Relative paths in `config.json` (`repo`, `data_dir`, `ssh_key`, the token
files, `forge_ca_file`) are read from the config file's folder. Without
`-c`, every key takes its default and the current folder is the
repository. The repository paths (`tofu_dir`, `inventory`, `playbooks`,
`roles`, `repo_settings`, `renovate_file`) are relative to `repo`.

Check a config without starting the server:

```sh
python3 cairn-iac.py -c cairn-iac.json --check
```

It reads the repository as the page would and prints one line per drift
finding (exit status 1 on a warning). Wrong paths stop it with the file it
could not read. `--json` instead prints the whole model: check `machines`,
`capacity` and `repo_settings` (which file was read, which keys it set,
its error) there.

## config.json

Every key is optional.

### The repository and the page

| Key | Type | Default | |
|---|---|---|---|
| `repo` | path | `"."` | root of the IaC repository; the server ignores it once `git.url` is set (it works on its own clone) |
| `title` | string | `"Cairn IaC"` | page header and tab title |
| `subtitle` | string | `""` | |
| `lang` | `""` \| `"en"` \| `"fr"` | `""` | the page's language when the viewer has not chosen one; empty: the browser's language, else English |
| `tofu_dir` | path | `"tofu"` | the Tofu root module; only its own `*.tf` are read |
| `inventory` | path | `"ansible/inventory/hosts.yml"` | YAML inventory |
| `playbooks` | path | `"ansible/playbooks"` | every `*.yml` in it is a playbook |
| `roles` | path | `"ansible/roles"` | |
| `node_group` | string | `"proxmox_nodes"` | inventory group of the Proxmox nodes: the columns of the map |
| `bare_metal_group` | string | `"bare_metal"` | inventory group of physical machines outside the cluster |
| `generic_playbooks` | list | `[]` | playbook names (no `.yml`) never shown as a machine's main playbook, such as fleet-wide upgrades |
| `required_roles` | list | `[]` | roles every inventory host must get; a host missing one is a drift warning |
| `node_capacity` | object | `{}` | see [`node_capacity`](#node_capacity) |
| `vcpu_ratio` | number | `1` | vCPU a node may give per declared core, between 1 and 64 (a bad value counts as 1) |
| `accepted_findings` | object | `{}` | finding id → reason, see [Drift findings](#drift-findings) |
| `repo_settings` | path | `".cairn-iac.json"` | see [The repository's settings file](#the-repositorys-settings-file); empty: none |
| `renovate_file` | path | `"renovate.json"` | the Updates view; empty: no view |
| `workflow` | object | `{}` | see [`workflow`](#workflow) |
| `note` | `{"title", "text"}` | none | an extra card on the overview; `` `code` `` in `text` is shown as code; no `text`: no card |
| `links` | object | `{}` | see [`links`](#links) |
| `firewall_lists` | `{"in", "out"}` | `{"in": "inbound_rules", "out": "outbound_rules"}` | server: the lists of a firewall module that receive new rules |
| `git` | object | see [`git`](#git) | server: the remote and how edits reach it |

Unknown keys are ignored, so a typo does not stop the page: it just has
no effect. If a setting seems ignored, check its spelling first.

`git` and `firewall_lists` are merged with their defaults: give only the
keys you change. `workflow`, `links` and `note` are taken as a whole.

**In server mode, the keys above are a seed.** At its first start the
server copies all of them but `repo` into `<data_dir>/settings.json`, and
from then on reads that file only: changing them in `config.json` later
has no effect on the server. Change them in Settings, or see
[The settings file](#the-settings-file). `--check`, `--json` and the
static page keep reading `config.json`.

### `node_capacity`

What each node can give its guests, by node name (any case, `_` = `-`):

```json
"node_capacity": {"pve1": {"cores": 8, "memory": 32, "disk": 1000}, "pve2": {"cores": 4, "memory": 16}}
```

| Key | |
|---|---|
| `cores` | physical cores; the bar's limit is `cores × vcpu_ratio` |
| `memory` | GiB (Tofu's MiB are converted) |
| `disk` | GB, shown in TB of 1024 GB once a node reaches it |

Whole numbers. A field left out has no bar and no check. A node over a
declared field is a drift warning.

### `workflow`

The words of the "path of a change" steps. All optional.

| Key | Default | |
|---|---|---|
| `example` | the first Tofu machine with roles | machine key shown first (lower case, `_` = `-`) |
| `workstation` | "your workstation" | where Tofu runs |
| `tofu` | `"tofu"` | the Tofu command; a wrapper such as `./tofu.sh` works |
| `reviewer` | none | who reviews the plan and applies it |
| `git_server` | none | named in the "the commit reaches …" step; none: step left out |
| `controller` | none | the Ansible controller's name |
| `controller_path` | none | its clone, put in front of `git pull` as `cd <path> &&` |
| `ansible` | `"ansible-playbook"` | the Ansible command |

### `links`

URL templates to your Git web UI. All optional.

| Key | |
|---|---|
| `name` | shown in "View in …" / "Edit in …"; default `Git` |
| `view` | `{file}` (repository-relative) and `{line}` |
| `edit` | `{file}` |
| `commit` | `{sha}`: the server's machine history links each commit |

Without `view` and `edit`, no link is shown.

### `git`

Server only.

| Key | Type | Default | |
|---|---|---|---|
| `url` | string | `""` | the remote (`ssh://…`); empty: the server works on `repo` and commits locally |
| `branch` | string | `"main"` | |
| `push` | bool | `true` | push after each commit |
| `mode` | `"push"` \| `"agit"` \| `"branch"` | `"push"` | `push`: onto the branch; `agit` (Forgejo/Gitea): `refs/for/<branch>`, the push opens a pull request; `branch`: a new branch per edit, open the pull request yourself |
| `name`, `email` | string | `"Cairn IaC"`, `"cairn-iac@localhost"` | the committer; the author is the signed-in user |
| `commit_prefix` | string | `""` | put before every commit message |
| `depth` | number | `200` | commits kept by the shallow clone, between 1 and 100000: how far back a machine's history goes |

Changing `url` in Settings throws the old clone away.

### Server: access and integrations

Read from `config.json` only, never from the page.

| Key | Type | Default | |
|---|---|---|---|
| `listen` | `"host:port"` | `"127.0.0.1:8080"` | `"0.0.0.0:8080"` in Docker |
| `data_dir` | path | `"data"` | settings, deploy key, clone, relative to the config file; with Docker set `"/var/lib/cairn-iac"`, the volume (the default would land in the read-only config folder) |
| `read_only` | bool | `false` | the page and Settings without editing |
| `trusted_proxies` | list | `[]` | addresses or CIDRs of the authenticating proxy; empty: only this machine (loopback), user `local` |
| `user_header` | string | `"Remote-User"` | |
| `groups_header` | string | `"Remote-Groups"` | comma-separated groups |
| `name_header`, `email_header` | string | `"Remote-Name"`, `"Remote-Email"` | the commit author; none: the user name |
| `require_groups` | list | `[]` | the user needs one of these groups; empty: any user |
| `ssh_key` | path | `""` | private key for the remote (its `.pub` beside it); empty: one is made in `data_dir` |
| `summary_token_file` | path | `""` | opens `GET /api/summary` to dashboards; empty: closed |
| `export_token_file` | path | `""` | opens `GET /api/export` (the `--json` model) to read-only aggregators such as Cairn Map; empty: closed |
| `forge_api` | URL | `""` | Forgejo/Gitea API (`https://git.example/api/v1`) |
| `forge_repo` | string | `""` | `owner/repo` |
| `forge_token_file` | path | `""` | a token that reads the repository; the three `forge_` keys set: open Renovate pull requests listed in Updates |
| `forge_ca_file` | path | `""` | CA bundle for the API's certificate; empty: the system's |

Token files hold one token, 32 characters at least (`openssl rand -hex
32`); a shorter one stops the server. The client sends
`Authorization: Bearer <token>`; each token opens its own endpoint only.

## The repository's settings file

`.cairn-iac.json` at the root of the IaC repository (`repo_settings`).
Its keys win over `config.json` and over the server's settings, so
`--check` in CI and the page agree.

```json
{"accepted_findings": {"not_in_tofu:nas": "made before the repository"},
 "vcpu_ratio": 4,
 "node_capacity": {"pve1": {"cores": 8, "memory": 32}},
 "required_roles": ["base"]}
```

| Key | Type |
|---|---|
| `accepted_findings` | object, string → string |
| `vcpu_ratio` | number |
| `node_capacity` | object of objects |
| `required_roles` | list of strings |

Only these four keys are read; any other is ignored. A key of the wrong
type is left out (the setting from the config stays) and the file shows as
a `repo_settings:.cairn-iac.json` warning; so does a file that is not a
JSON object. A missing file is fine. A path that leaves the repository
(leading `/`, `..`) is ignored.

The server's Accept button writes `accepted_findings` in this file, as a
commit like any edit (a pull request in `agit` or `branch` mode: the
acceptance counts once merged).

## Drift findings

Each finding has an `id`, printed by `--check --json`. To keep one on
purpose, add it to `accepted_findings` with a reason: it stays listed,
greyed, and `--check` no longer fails on it.

| `id` | Severity | |
|---|---|---|
| `not_in_inventory:<machine>` | warn | a Tofu machine absent from the inventory |
| `ip_mismatch:<machine>` | warn | Tofu and `ansible_host` disagree |
| `required_roles:<machine>` | warn | a host missing one of `required_roles` |
| `firewall_orphan:<machine>` | warn | a firewall whose id matches no machine |
| `firewall_off:<machine>` | warn | a guest firewall turned off that has rules |
| `over_allocated:<node>:<cores\|memory\|disk>` | warn | a node given more than its `node_capacity` |
| `repo_settings:<file>` | warn | the repository's settings file cannot be used |
| `not_in_tofu:<machine>` | info | an inventory host no Tofu block creates |
| `no_playbook:<machine>` | info | an inventory host no playbook targets |
| `firewall_no_options:<machine>` | info | rules without a firewall options resource |
| `half_open:<machine>:<from>><to>:<what>` | info | a flow allowed on one side only |

`<machine>` is the machine's key: its name in lower case, `_` written
`-`. The id names what the finding is about, not its numbers: an accepted
`over_allocated` stays accepted when the amounts change.

## The settings file

`<data_dir>/settings.json`, written by the server's Settings page,
atomically. It holds every key of
[The repository and the page](#the-repository-and-the-page) except
`repo`, created from `config.json` at the first start. A key missing from
it takes its default (not the config's value).

Settings checks what it saves: names for `generic_playbooks`,
`required_roles` and the nodes, `vcpu_ratio` from 1 to 64, a reason (200
characters at most) for each accepted finding, repository paths without a
leading `/` nor `..`, `repo_settings` and `renovate_file` ending in
`.json`, `git.mode` among the three, `git.depth` from 1 to 100000.

You can edit it by hand: stop the server, edit, start it again. To go back
to what `config.json` says, delete the file and restart.

## Files written by the server

All in `data_dir`:

| File | |
|---|---|
| `settings.json` | above |
| `id_ed25519`, `id_ed25519.pub` | the deploy key, made at first start when `ssh_key` is empty; shown in Settings, give it write access to the repository |
| `known_hosts` | the remote's host key, accepted on first use |
| `repo/` | the shallow clone of `git.url`, reset to the remote branch at most every 30 s |

Deleting `repo/` is safe: the next sync clones it again.

## Recipes

**Smallest useful config**: a static page, the config file at the
repository's root.

```json
{"title": "My lab"}
```

```sh
python3 cairn-iac.py -c cairn-iac.json -o iac.html
```

**CI with no config file**: run from the repository's root with
`python3 path/to/cairn-iac.py --check`; it takes the defaults and
`.cairn-iac.json`. Put there everything CI must agree with:

```json
{"required_roles": ["base"], "vcpu_ratio": 4, "accepted_findings": {"no_playbook:printer": "managed by hand"}}
```

**Behind Authelia (or any authenticating proxy)**: listen on the network,
answer only the proxy, and keep editing to one group.

```json
{"listen": "0.0.0.0:8080", "data_dir": "/var/lib/cairn-iac",
 "trusted_proxies": ["10.0.10.5"], "require_groups": ["admins"],
 "git": {"url": "ssh://git@git.example:22/me/iac.git", "branch": "main"}}
```

**Every edit as a pull request** (Forgejo/Gitea), with the open Renovate
pull requests in Updates:

```json
{"git": {"url": "ssh://git@git.example:22/me/iac.git", "mode": "agit", "commit_prefix": "iac: "},
 "forge_api": "https://git.example/api/v1", "forge_repo": "me/iac", "forge_token_file": "forge-token"}
```

**A read-only page for the whole team**, and a feed for Cairn Map:

```json
{"listen": "0.0.0.0:8080", "trusted_proxies": ["10.0.10.5"], "read_only": true,
 "export_token_file": "export-token"}
```

**Links to GitHub**:

```json
"links": {"name": "GitHub",
          "view": "https://github.com/me/iac/blob/main/{file}#L{line}",
          "edit": "https://github.com/me/iac/edit/main/{file}",
          "commit": "https://github.com/me/iac/commit/{sha}"}
```

**Try a change without touching the server**: copy its settings into a
config next to the repository and run `--check` or `--json`.
