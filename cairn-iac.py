#!/usr/bin/env python3
"""cairn-iac: one static HTML page showing what an OpenTofu + Ansible repo builds.

For each machine: what Tofu creates (CPU, memory, disk, IP, the HCL block),
its guest firewall, and the Ansible roles it receives (with their task names).

    python3 cairn-iac.py -c cairn-iac.json -o iac.html

Needs Python 3.8+ and PyYAML (Debian: python3-yaml). Reads files only; never
runs tofu or ansible.
"""
import argparse, json, pathlib, re, subprocess, sys

try:
    import yaml
except ImportError:
    sys.exit("cairn-iac: PyYAML is required (Debian: apt install python3-yaml, else pip install pyyaml)")

HERE = pathlib.Path(__file__).resolve().parent
DEFAULTS = {
    "repo": ".", "title": "Cairn IaC", "subtitle": "", "lang": "",
    "tofu_dir": "tofu", "inventory": "ansible/inventory/hosts.yml",
    "playbooks": "ansible/playbooks", "roles": "ansible/roles",
    "node_group": "proxmox_nodes", "bare_metal_group": "bare_metal",
    "generic_playbooks": [], "note": None, "links": {},
    "workflow": {},
}
VM_RESOURCES = ("proxmox_virtual_environment_vm", "proxmox_virtual_environment_container")


def key(name):
    """Inventory host names and Tofu names compared case- and _/- insensitively."""
    return name.lower().replace("_", "-")


def blocks(text):
    """Top-level HCL blocks: (kind, label1, label2), first line number, leading comment, body."""
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        m = re.match(r'^(module|resource) "([^"]+)"(?: "([^"]+)")? *\{', lines[i])
        if m:
            start = c = i
            while c > 0 and lines[c - 1].startswith("#"):
                c -= 1
            while i < len(lines) and lines[i] != "}":
                i += 1
            yield m.groups(), start + 1, "\n".join(lines[start:i + 1])
        i += 1


def val(body, k):
    m = re.search(rf'^\s*{k}\s*=\s*"?([^"\n]+?)"?\s*$', body, re.M)
    return m.group(1) if m else None


def kv(text, k):
    m = re.search(rf'\b{k}\s*=\s*"([^"]*)"', text)
    return m.group(1) if m else None


def read_tofu(tofu_dir, repo):
    machines, firewalls = [], {}
    for tf in sorted(tofu_dir.glob("*.tf")):
        rel = tf.relative_to(repo).as_posix()
        for (kind, a, b), line, body in blocks(tf.read_text(encoding="utf-8")):
            cid = val(body, "container_id") or val(body, "vm_id")
            # Guest firewall: provider rules resource, or a module taking lists of rule objects.
            rules = None
            if kind == "resource" and a == "proxmox_virtual_environment_firewall_rules":
                rules = [(kv(r, "type") or "in", r) for r in re.findall(r'rule \{(.*?)\n  \}', body, re.S)]
            elif kind == "module" and re.search(r'^  \w+_rules\s*=\s*\[', body, re.M):
                rules = []
                for sec in re.finditer(r'^  (\w+_rules)\s*=\s*\[(.*?)^  \]', body, re.S | re.M):
                    d = "out" if re.search(r"egress|outbound|out_", sec.group(1)) else "in"
                    rules += [(d, r) for r in re.findall(r'\{(.*?)\}', sec.group(2), re.S)]
            if rules is not None and cid:
                label = b if kind == "resource" else a
                fw = firewalls.setdefault(cid, {"name": re.sub(r"^(firewall|fw)_", "", label), "node": val(body, "node_name"),
                                                "file": rel, "line": line, "rules": []})
                fw["rules"] += [{"dir": d, **{k: kv(r, k) for k in ("proto", "dport", "source", "dest", "comment")}} for d, r in rules]
                continue
            # Machines: the provider's VM/container resources, or any module given a vm_id.
            if (kind == "resource" and a in VM_RESOURCES) or (kind == "module" and val(body, "vm_id")):
                name = val(body, "hostname") or val(body, "name") or (b or a)
                machines.append({
                    "name": name, "kind": "LXC" if (kind == "module" or a.endswith("container")) else "VM",
                    "address": f"module.{a}" if kind == "module" else f"{a}.{b}",
                    "node": val(body, "node_name"), "id": int(val(body, "vm_id") or 0) or None,
                    "cores": val(body, "cores"), "memory": val(body, "memory") or val(body, "dedicated"),
                    "disk": val(body, "disk_size") or val(body, "size"),
                    "ip": ((val(body, "ip_address") or val(body, "address") or "").split("/")[0]),
                    "file": rel, "line": line, "code": body,
                })
    return machines, firewalls


def read_ansible(cfg, repo):
    inv = yaml.safe_load((repo / cfg["inventory"]).read_text(encoding="utf-8"))
    children = (inv.get("all") or inv).get("children") or {}
    groups, ips = {}, {}

    def walk(name, d):
        d = d or {}
        hosts = list((d.get("hosts") or {}).keys())
        for h, v in (d.get("hosts") or {}).items():
            if v and "ansible_host" in v:
                ips[h] = v["ansible_host"]
            ips.setdefault(h, "")
        for c, cd in (d.get("children") or {}).items():
            hosts += walk(c, cd)
        groups[name] = sorted(set(hosts))
        return hosts

    for g, d in children.items():
        walk(g, d)
    for h, v in ((inv.get("all") or {}).get("hosts") or {}).items():
        ips.setdefault(h, (v or {}).get("ansible_host", ""))
    allhosts = sorted(ips)

    def resolve(pattern):
        # ponytail: "!host" and "&group" patterns are skipped, not applied.
        out = set()
        for p in re.split(r"[,:]", str(pattern or "")):
            p = p.strip()
            if not p or p[0] in "!&":
                continue
            out |= set(allhosts) if p in ("all", "*") else set(groups.get(p, [p]))
        return sorted(out)

    playbooks = {}
    for f in sorted((repo / cfg["playbooks"]).glob("*.yml")):
        try:
            plays = yaml.safe_load(f.read_text(encoding="utf-8")) or []
        except yaml.YAMLError as e:
            print(f"cairn-iac: skipped {f.name}: {e}", file=sys.stderr)
            continue
        items = []
        for p in plays if isinstance(plays, list) else []:
            if not isinstance(p, dict) or "hosts" not in p:
                continue
            roles = [r if isinstance(r, str) else r.get("role") or r.get("name") for r in p.get("roles") or []]
            for t in (p.get("pre_tasks") or []) + (p.get("tasks") or []):
                for k in ("include_role", "import_role", "ansible.builtin.include_role", "ansible.builtin.import_role"):
                    if isinstance(t, dict) and isinstance(t.get(k), dict):
                        roles.append(t[k].get("name"))
            items.append({"hosts": resolve(p["hosts"]), "roles": [r for r in roles if r]})
        playbooks[f.stem] = items

    roles = {}
    roles_dir = repo / cfg["roles"]
    for d in sorted(p for p in roles_dir.iterdir() if p.is_dir()) if roles_dir.exists() else []:
        tasks = []
        for tf in sorted((d / "tasks").glob("*.yml")):
            tasks += re.findall(r'^- name: (.+)$', tf.read_text(encoding="utf-8"), re.M)
        about = ""
        main = d / "tasks/main.yml"
        if main.exists():
            head = []
            for l in main.read_text(encoding="utf-8").splitlines():
                if l.startswith("#"):
                    head.append(l.lstrip("# "))
                elif l.strip() and l.strip() != "---":
                    break
            about = "\n".join(head[:8])
        templates = sorted(p.name for p in (d / "templates").glob("*")) if (d / "templates").exists() else []
        roles[d.name] = {"tasks": tasks, "about": about, "templates": templates}
    return groups, ips, playbooks, roles


def git_rev(repo):
    try:
        return subprocess.run(["git", "-C", str(repo), "log", "-1", "--format=%h %cs"],
                              capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return ""


def build(cfg_path, out_path):
    cfg = {**DEFAULTS, **(json.loads(cfg_path.read_text(encoding="utf-8")) if cfg_path else {})}
    base = cfg_path.parent if cfg_path else pathlib.Path.cwd()
    repo = (base / cfg["repo"]).resolve()
    machines, firewalls = read_tofu(repo / cfg["tofu_dir"], repo)
    groups, ips, playbooks, roles = read_ansible(cfg, repo)
    inv_parent = (repo / cfg["inventory"]).parent.parent
    try:
        pb_prefix = (repo / cfg["playbooks"]).relative_to(inv_parent).as_posix() + "/"
    except ValueError:
        pb_prefix = cfg["playbooks"].rstrip("/") + "/"
    data = {
        "title": cfg["title"], "subtitle": cfg["subtitle"], "lang": cfg["lang"], "rev": git_rev(repo),
        "workflow": cfg["workflow"], "note": cfg["note"], "playbook_prefix": pb_prefix,
        "generic_playbooks": cfg["generic_playbooks"], "links": cfg["links"],
        "paths": {k: pathlib.PurePosixPath(cfg[k]).as_posix() for k in ("inventory", "playbooks", "roles")},
        "nodes": groups.get(cfg["node_group"], []), "bare": groups.get(cfg["bare_metal_group"], []),
        "tofu": machines, "firewalls": firewalls, "groups": groups, "ips": ips,
        "playbooks": playbooks, "roles": roles,
    }
    page = (HERE / "page.html").read_text(encoding="utf-8")
    blob = json.dumps(data, ensure_ascii=False).replace("</", "<\\u002f")
    page = page.replace("/*DATA*/null", blob).replace("<title>Cairn IaC</title>", f"<title>{escape(cfg['title'])}</title>")
    out_path.write_text(page, encoding="utf-8", newline="\n")
    print(f"cairn-iac: {out_path} ({len(machines)} Tofu machines, {len(firewalls)} firewalls, "
          f"{len(ips)} inventory hosts, {len(playbooks)} playbooks, {len(roles)} roles)")


def escape(s):
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("-c", "--config", type=pathlib.Path, help="JSON config (default: none, current directory is the repo)")
    ap.add_argument("-o", "--output", type=pathlib.Path, default=pathlib.Path("iac.html"))
    a = ap.parse_args()
    build(a.config.resolve() if a.config else None, a.output)
