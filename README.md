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
and no credentials. The output is a single self-contained page (no external
script, font or request), to open locally or serve from anywhere.

> Interface in English and French. Built for its author's homelab and made
> generic; issues and pull requests are welcome. Same design system as
> [Cairn](https://github.com/JBelliriGenty/Cairn-NAS).

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

### Editing from the page

The page stays read-only: with `links`, every Tofu block, firewall, role,
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
