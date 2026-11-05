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

A Roles view lists every role with the machines that get it, and the
machine map can highlight the machines of one role.

It reads files only: it never runs `tofu` or `ansible`, needs no state file
and no credentials. An optional server mode adds editing from the page,
committed and pushed to Git (see Server). The output is a single self-contained page (no external
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
    (a list whose name contains `egress` or `outbound` is outgoing).
- **Ansible**: the YAML inventory (nested `children` groups included), every
  `*.yml` playbook (`hosts` patterns resolved by group, `roles` and
  `include_role`/`import_role` tasks), and each role's `tasks/*.yml` task
  names, its leading comment and its `templates/`.

Machines are matched across Tofu, firewalls and inventory by `vm_id` and by
name (case-insensitive, `_` = `-`).

Not followed: exclusion patterns (`!host`, `&group`), roles included by
other roles, `import_playbook`, values computed in HCL (`var.`, `local.`).

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
| `workflow` | words of the change path, see below |
| `note` | `{title, text}`: an extra card on the overview; `` `code` `` in `text` is shown as code |
| `links` | `{name, view, edit}`: "View in / Edit in" links to your Git web UI, URL templates with `{file}` (repo-relative) and `{line}` |

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
          "edit": "https://git.example/me/iac/_edit/main/{file}"}
```

GitHub: `…/blob/main/{file}#L{line}` and `…/edit/main/{file}`; GitLab:
`…/-/blob/main/{file}#L{line}` and `…/-/edit/main/{file}`.

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
- give it a role, as a new play appended to a playbook.

Every edit is shown as a diff first; the file is parsed again to check the
result. Then it is committed, **authored by the signed-in user** (the
proxy's `Remote-Name` / `Remote-Email`, else the user name), committed by
the server's identity, and pushed. A refused push leaves nothing behind:
the clone is reset to the remote. It still never runs `tofu` or
`ansible`: plan/apply and playbooks stay yours, as the change path shows.

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
| `ssh_key` | private key for the Git remote, e.g. one already allowed on the repository (`.pub` beside it); empty: generated in `data_dir` |
| `firewall_lists` | `{in, out}`: list names that receive new rules in a firewall module (`inbound_rules`, `outbound_rules`) |
| `git` | `{url, branch, push, mode, name, email, commit_prefix}`: remote, branch (`main`), push after each commit (`true`), `mode`: `push` onto the branch, `agit` (Forgejo/Gitea: `refs/for/<branch>` opens a pull request, no API token), `branch` (a new branch per edit, open the pull request yourself); committer identity |

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
