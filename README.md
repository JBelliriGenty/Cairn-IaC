# Cairn IaC (`cairn-iac`)

One static HTML page that shows what an **OpenTofu + Ansible** repository
for **Proxmox** actually builds. For each machine:

- **the box**, from Tofu: vCPU, memory, disk, IP, node, and the exact HCL
  block with its file and line;
- **its guest firewall**, from Tofu: every rule with its direction, port,
  peer and comment;
- **its content**, from Ansible: inventory groups, the roles it receives
  (each one unfolds to its task names), the playbooks that target it;
- **the path of a change**, for that machine: the `tofu plan -target` /
  `apply` commands, then `git push`, `git pull` on the controller and
  `ansible-playbook … -l <host> --check --diff`.

A Roles view lists every role with the machines that get it. The machine
map shows each node's capacity (see Node capacity), can highlight the
machines of one role, and has a search field (`/` focuses it) matching
names, IPs, ids, roles, groups and nodes. A Flows view shows
who may talk to whom (see Flows). A Drift view lists
where the repository disagrees with itself (see Drift), also available from
the command line for CI. The whole model can be exported as JSON (see
JSON export).

It reads files only: it never runs `tofu` or `ansible`, needs no state file
and no credentials. It never reads a Tofu state (`*.tfstate`,
`*.tfstate.backup`) or a saved plan (`*.plan`), which can hold secrets:
only `*.tf` files. An optional server mode adds editing from the page,
committed and pushed to Git, including a new machine copied from an existing
one (see Server). The output is a single self-contained page (no external
script, font or request), to open locally or serve from anywhere.

> Interface in English and French. Issues and pull requests are welcome.
> Same design system as [Cairn](https://github.com/JBelliriGenty/Cairn-NAS).

## Use

Python 3.8+ and PyYAML (Debian: `apt install python3-yaml`):

```sh
python3 cairn-iac.py -c cairn-iac.json -o iac.html
```

Try it on the bundled example:

```sh
python3 cairn-iac.py -c example/cairn-iac.json -o example.html
```

To keep the page current, run it from CI or a timer after each `git pull`
and serve the file with any web server.

## What it understands

- **Tofu** (`*.tf` at the top of `tofu_dir`, modules are not followed):
  - machines: `proxmox_virtual_environment_vm` and
    `proxmox_virtual_environment_container` resources
    ([bpg/proxmox](https://registry.terraform.io/providers/bpg/proxmox)), and
    any `module` block given a `vm_id` (your own LXC/VM module). Read keys:
    `node_name`, `vm_id`, `hostname` or `name`, `cores`, `memory` or
    `dedicated`, `disk_size` or `size`, `ip_address` or `address`;
  - firewalls: `proxmox_virtual_environment_firewall_rules` resources, and
    modules with a `container_id`/`vm_id` and `*_rules = [ { … } ]` lists
    (a list whose name contains `egress` or `outbound` is outgoing); whether
    a guest firewall is on, and its input policy, from
    `proxmox_virtual_environment_firewall_options` resources or from the
    `enabled` / `input_policy` / `output_policy` arguments of a firewall
  module; for a local firewall module (`source = "./…"`), the literal
  `rule { … }` blocks written in the module itself (common to every
  machine using it; a `var.` value comes from the module call's literal
  argument, else from the variable's literal default; a rule with any other
  computed value is skipped).
- **Ansible**: the YAML inventory (nested `children` groups included), every
  `*.yml` playbook (`hosts` patterns resolved by group, `roles` and
  `include_role`/`import_role` tasks), and each role's `tasks/*.yml` task
  names, its leading comment and its `templates/`.

Machines are matched across Tofu, firewalls and inventory by `vm_id` and by
name (case-insensitive, `_` = `-`).

Not followed: other modules' contents, exclusion patterns (`!host`, `&group`), roles included by
other roles, `import_playbook`, values computed in HCL (`var.`, `local.`).

## Flows

The Flows view lists one flow per guest firewall rule: an incoming rule on
B gives source → B, an outgoing rule on A gives A → destination. Each
address is resolved to the machines it covers (by Tofu IP, then
`ansible_host`): one machine, a network (with the number of machines in
it), a list of addresses, or anywhere (no address, or `0.0.0.0/0`). Pick a
machine to see who can reach it and what it can reach (networks that
include it come after the machine itself); the rules common to a firewall
module are hidden unless asked for. Each flow links to the machine and to
its file and line.

## Node capacity

Each node's column on the machine map sums the vCPU, memory (MiB) and
disk (GB) that Tofu gives the guests on that node. A value Tofu does not
write as a literal number (a variable, a `local.`, nothing) is not counted:
the column says how many guests are unknown, and which ones on hover. Only
the first `disk_size`/`size` of a block is read (a VM with several disks
counts its first one).

With `node_capacity` (`{node: {cores, memory, disk}}`, memory in GiB, disk in GB (shown in TB of 1024 GB once a node reaches it), in the
config or in Settings), each sum gets a bar against the node's capacity:
amber past 80 %, red past 100 %, and a node over its capacity is a drift
warning. vCPU are often overcommitted on purpose: declare the number you
accept, not the physical cores.

## JSON export

```sh
python3 cairn-iac.py -c cairn-iac.json --json > model.json
```

Prints what the page shows as JSON, for other tools: `title`, `rev`,
`machines` (one per machine, merged from Tofu, the firewalls and the
inventory: `key`, `name`, `host`, `node`, `id`, `ip`, `phys`, `tofu`
(kind, address, cores, memory, disk, file, line), `firewall` (its id in
`firewalls`), `groups`, `roles`, `playbooks`), `capacity` (per node:
`guests`, `cores`, `memory`, `disk`, `unknown`, `total`; memory in MiB everywhere there), `firewalls`,
`roles`, `playbooks`, `groups`, `findings` and `flows`. No HCL block nor any
other file content. The page's "Download JSON" button gives the same file,
from the data already in the page.

## Drift

The Drift view (with a count in the menu and on the overview) and
`--check` list the same findings. Warnings:

- a Tofu machine absent from the inventory;
- an IP that differs between Tofu and `ansible_host`;
- a firewall whose `container_id`/`vm_id` matches no machine (neither a
  Tofu machine nor, by name, an inventory host);
- a guest firewall turned off (`enabled = false`) that has rules: they
  protect nothing;
- an inventory host missing one of the `required_roles`;
- a node given more vCPU, memory or disk than its `node_capacity`.

Notes (they can be on purpose):

- an inventory host no Tofu block creates, outside the node and
  bare-metal groups;
- an inventory host no playbook targets;
- firewall rules (provider resource) without a firewall options resource:
  Proxmox keeps a guest firewall off until it is turned on;
- a half-open flow, between two single machines: an outgoing rule on A to
  B that no incoming rule on B lets in, or an incoming rule on B from A
  that no outgoing rule on A lets out. Only checked where the other side
  filters that direction (input policy not `ACCEPT`; output policy `DROP`
  or `REJECT`, or not written and the firewall has outgoing rules), and
  where A's address is known. A rule given by a macro, without protocol or
  port, matches any traffic.

```sh
python3 cairn-iac.py -c cairn-iac.json --check         # one line per finding, exit 1 on a warning
python3 cairn-iac.py -c cairn-iac.json --check --json  # the same, as JSON
```

Each JSON finding: `kind`, `severity` (`warn` or `info`), `machine`,
`file`, `line`, `msg` (an English template) and its `vars`. A capacity
finding has no file (`""`, line 0): its `machine` is the node.

## Configuration (JSON)

Every key is optional; paths are relative to the config file.

| Key | Purpose (default) |
|---|---|
| `repo` | root of the IaC repository (`.`) |
| `title`, `subtitle` | page header (`Cairn IaC`) |
| `lang` | `en` or `fr`: the page's default when the viewer has not chosen (browser language) |
| `tofu_dir` | Tofu root module (`tofu`) |
| `inventory` | Ansible inventory (`ansible/inventory/hosts.yml`) |
| `playbooks`, `roles` | Ansible directories (`ansible/playbooks`, `ansible/roles`) |
| `node_group` | inventory group of the Proxmox nodes, shown as map columns (`proxmox_nodes`) |
| `bare_metal_group` | inventory group of physical machines outside the cluster (`bare_metal`) |
| `generic_playbooks` | playbook names (no `.yml`) never shown as a machine's main playbook, e.g. fleet-wide upgrades |
| `required_roles` | roles every inventory machine must get, checked in Drift (empty) |
| `node_capacity` | `{node: {cores, memory, disk}}`: what each node can give its guests, memory in GiB, disk in GB (empty: sums only) |
| `workflow` | words of the change path, see below |
| `note` | `{title, text}`: an extra card on the overview; `` `code` `` in `text` is shown as code |
| `links` | `{name, view, edit, commit}`: "View in / Edit in" links to your Git web UI, URL templates with `{file}` (repo-relative) and `{line}`; `commit` with `{sha}`, for the machine history (server) |

`workflow` keys: `example` (machine shown first), `workstation` (where Tofu
runs), `tofu` (command, `tofu`; a wrapper such as `./tofu.sh` works),
`reviewer` (who reviews the plan), `git_server`, `controller` (the Ansible
controller's name), `controller_path` (its clone), `ansible`
(`ansible-playbook`).

```json
{
  "repo": "..",
  "title": "My lab",
  "lang": "en",
  "generic_playbooks": ["upgrade"],
  "workflow": {"workstation": "my laptop", "tofu": "./tofu.sh", "git_server": "Forgejo",
               "controller": "ansible01", "controller_path": "/srv/iac"}
}
```

### Links to your Git web UI

With `links`, every Tofu block, firewall, role,
playbook and the inventory get a link to your Git web UI, where the change
is made and committed under your own account. Then plan/apply or run the
playbook as the change path shows. Forgejo / Gitea:

```json
"links": {"name": "Forgejo",
          "view": "https://git.example/me/iac/src/branch/main/{file}#L{line}",
          "edit": "https://git.example/me/iac/_edit/main/{file}",
          "commit": "https://git.example/me/iac/commit/{sha}"}
```

GitHub: `…/blob/main/{file}#L{line}`, `…/edit/main/{file}` and
`…/commit/{sha}`; GitLab: `…/-/blob/main/{file}#L{line}`,
`…/-/edit/main/{file}` and `…/-/commit/{sha}`. `commit` links the server's
machine history (below) to each commit.

## Server: edit from the page, commit and push

```sh
python3 cairn-iac.py -c server.json --serve
```

The same page, served by a small built-in server (Python standard library,
plus `git` and `ssh`). Each machine gets forms to:

- change its vCPU, memory and disk (literal numbers in the block; a disk
  never shrinks);
- add or remove a guest firewall rule (provider `rule { … }` blocks, or one
  `{ … }` object per line in a module's rule lists);
- add it to or remove it from an inventory group (a machine new to the
  inventory gets its `ansible_host`; a host with variables in that group is
  left to you);
- give it a role: appended to the block-style `roles:` list of a play whose
  `hosts` is exactly that machine in the chosen playbook, else as a new play
  at its end.

A **New machine** page (and a "New machine from this one" link on each
Tofu machine) copies a model, picked among the Tofu machines, in one
commit:

- its Tofu block, appended to the same file with the new name (`hostname`
  or `name`, and the block label made from it), `vm_id`, `node_name`,
  address (same prefix length and gateway as the model), vCPU, memory and
  disk, a `description` and the model's name in `tags` replaced; the
  comments naming the model are left out, a comment with the description
  goes above;
- its guest firewall block(s) (rules resource and options resource, or the
  firewall module call), renamed and pointed at the new id, node and
  `depends_on`, the model's own address in its rules replaced; with the
  model's rules, or with none of its own (a module keeps its common rules);
- the host in the inventory groups picked (the model's direct groups by
  default), with its `ansible_host` in the group where the model has its
  own; optionally a role in a playbook, as above.

It refuses rather than guesses: the name must be new to Tofu and the
inventory, the `vm_id` unused by any Tofu block (100 to 999999999), the
node a known one, the address a host address of the model's network that
no tracked file of the repository names yet (`git grep`), the resources
within the limits; the model's name, id, node, address and changed
resources must be literal values, and its code must not refer to other
resources of its own (a cloud-init file, say). The files are parsed again:
the new machine must appear exactly once in Tofu, its firewall once, the
host once in the inventory. **Nothing is created** until you plan and apply
the new blocks: the preview shows the `tofu plan -target=… -target=…`
and `apply` commands, then run the playbooks on the new host.

Every edit is shown as a diff first (all files of the commit); the files
are parsed again to check the result. Then it is committed, **authored by the signed-in user** (the
proxy's `Remote-Name` / `Remote-Email`, else the user name), committed by
the server's identity, and pushed. A refused push leaves nothing behind:
the clone is reset to the remote. It still never runs `tofu` or
`ansible`: plan/apply and playbooks stay yours, as the change path shows.

The pull request is opened by the server's key, so the Git server shows
that account as its author. In `agit` mode the push also sets the pull
request's description: "Proposed by *name* (*user*) from Cairn IaC", then
the commit message body, on one line (push options cannot hold a line
break). In `branch` mode you open the pull request yourself; the commit
inside it carries the author either way.

Each machine also has a **History**, loaded when opened: the latest 15
commits touching its Tofu block, its firewall block(s), its inventory
entries or the plays aimed at it (`git log -L`), and inventory or playbook
changes naming it (`git log -G`), newest first, cached per commit. The
server's clone is shallow (`git.depth`, 200 commits): when the history
reaches that limit, the page says so and from which date nothing older was
fetched; raise `git.depth` to go further back.

A **Settings** page holds everything about the page and the repository
(the keys of the table above, `firewall_lists` and `git`). It is stored in
`<data_dir>/settings.json`, seeded once from the config file. With a
`git.url`, the server keeps its own shallow clone in `data_dir`, resets it
to the remote branch at most every 30 s, and generates an ed25519 **deploy
key** at first start, shown in Settings: give it write access to the
repository. Without `git.url`, it works on `repo` and commits locally.

Who may use it is set in the config file only, never from the page:

| Key | Purpose (default) |
|---|---|
| `listen` | address and port (`127.0.0.1:8080`) |
| `data_dir` | settings, deploy key, clone (`data`) |
| `trusted_proxies` | addresses (or CIDRs) of the authenticating reverse proxy; empty: requests from this machine only, user `local` |
| `user_header`, `groups_header` | headers set by the proxy (`Remote-User`, `Remote-Groups`) |
| `name_header`, `email_header` | commit author (`Remote-Name`, `Remote-Email`) |
| `require_groups` | at least one of these groups (empty: any signed-in user) |
| `read_only` | page and Settings without editing (`false`) |
| `summary_token_file` | file holding a token (32 characters min., `openssl rand -hex 32`) that opens `GET /api/summary` to dashboards with `Authorization: Bearer <token>`: `machines`, `firewalls`, `roles`, `warnings`, `notes` (drift), `rev`, `error` (empty: closed) |
| `ssh_key` | private key for the Git remote, e.g. one already allowed on the repository (`.pub` beside it); empty: generated in `data_dir` |
| `firewall_lists` | `{in, out}`: list names that receive new rules in a firewall module (`inbound_rules`, `outbound_rules`) |
| `git` | `{url, branch, push, mode, name, email, commit_prefix, depth}`: remote, branch (`main`), push after each commit (`true`), `mode`: `push` onto the branch, `agit` (Forgejo/Gitea: `refs/for/<branch>` opens a pull request, no API token), `branch` (a new branch per edit, open the pull request yourself); committer identity; commits kept in the clone, as far back as the machine history goes (`200`) |

```json
{
  "listen": "0.0.0.0:8080", "data_dir": "/var/lib/cairn-iac",
  "trusted_proxies": ["10.0.0.5"], "require_groups": ["admins"],
  "title": "My lab",
  "git": {"url": "ssh://git@git.example:22/me/iac.git", "branch": "main"}
}
```

Put it behind an authenticating proxy (Authelia, oauth2-proxy, …) that
sets the user headers and strips them from the client; nothing else may
reach the port. Forms only send JSON to the same origin (no cookie, no
CORS), and every edit checks that the repository has not moved since the
page was loaded.

An image is published for each release (Alpine, amd64 and arm64, runs as
`nobody`):

```sh
docker run -d -p 8080:8080 -v $PWD/server.json:/etc/cairn-iac/config.json:ro -v cairn-iac:/var/lib/cairn-iac ghcr.io/jbellirigenty/cairn-iac:1
```

Or build it from the included `Dockerfile`: `docker build -t cairn-iac .`

## Translations

The page's code is written in English. To add a language: copy the `FR`
table of `page.html`, translate its values, and add the language to `DICT`
and `LANGS`. Plurals follow the language's own rule (`Intl.PluralRules`).

## Test

```sh
python3 test_cairn_iac.py
```

## License

MIT, see `LICENSE`.
