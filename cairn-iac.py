#!/usr/bin/env python3
"""cairn-iac: one HTML page showing what an OpenTofu + Ansible repo builds.

For each machine: what Tofu creates (CPU, memory, disk, IP, the HCL block),
its guest firewall, and the Ansible roles it receives (with their task names).

    python3 cairn-iac.py -c cairn-iac.json -o iac.html      # static page
    python3 cairn-iac.py -c server.json --serve             # page + edits, Git commit and push
    python3 cairn-iac.py -c cairn-iac.json --check [--json] # drift list, exit 1 on a warning (CI)
    python3 cairn-iac.py -c cairn-iac.json --json           # the whole model as JSON, for other tools

Needs Python 3.8+ and PyYAML (Debian: python3-yaml); the server also needs git
(and ssh for an ssh:// remote). Never runs tofu or ansible.
"""
import argparse, base64, difflib, http.server, ipaddress, json, os, pathlib, re, shutil, subprocess, sys, threading, time, urllib.parse

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
    # links: {name, view, edit, commit}, URL templates of the Git web UI ({file}, {line}; {sha} for commit).
    "generic_playbooks": [], "note": None, "links": {},
    # Roles every inventory machine must get (drift view and --check); empty: not checked.
    "required_roles": [],
    # What each Proxmox node can give its guests: {node: {cores, memory (GiB), disk (GB)}}; empty: sums only.
    "node_capacity": {},
    "workflow": {},
    # Server only: where new guest firewall rules go in a firewall module.
    "firewall_lists": {"in": "inbound_rules", "out": "outbound_rules"},
    # mode: push (to the branch), branch (a new branch per edit, to open a pull request from),
    # agit (Forgejo/Gitea AGit: refs/for/<branch> opens the pull request itself).
    # depth: commits kept by the server's clone, as far back as a machine's history goes.
    "git": {"url": "", "branch": "main", "push": True, "mode": "push", "name": "Cairn IaC", "email": "cairn-iac@localhost", "commit_prefix": "",
            "depth": 200},
}
# Keys the Settings page edits (stored in <data_dir>/settings.json, seeded once from the config).
SETTINGS = [k for k in DEFAULTS if k != "repo"]
SERVER = {
    "listen": "127.0.0.1:8080", "data_dir": "data", "read_only": False,
    # SSH private key for the Git remote (its .pub beside it); empty: one is generated in data_dir.
    "ssh_key": "",
    # Behind an authenticating proxy: requests from these addresses only, user from user_header.
    # Empty: requests from this machine only (loopback), user "local".
    "trusted_proxies": [], "user_header": "Remote-User", "groups_header": "Remote-Groups",
    "name_header": "Remote-Name", "email_header": "Remote-Email", "require_groups": [],
}
VM_RESOURCES = ("proxmox_virtual_environment_vm", "proxmox_virtual_environment_container")
FW_RESOURCE = "proxmox_virtual_environment_firewall_rules"
FW_OPTIONS = "proxmox_virtual_environment_firewall_options"


def key(name):
    """Inventory host names and Tofu names compared case- and _/- insensitively."""
    return name.lower().replace("_", "-")


def blocks(text):
    """Top-level HCL blocks: (kind, label1, label2), first line number, body."""
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        m = re.match(r'^(module|resource) "([^"]+)"(?: "([^"]+)")? *\{', lines[i])
        if m:
            start = i
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


def is_firewall(kind, a, body):
    # A firewall module with no rules of its own (base rules only) is still a firewall, not a machine.
    return (kind == "resource" and a == FW_RESOURCE) or (kind == "module" and bool(
        re.search(r'^  \w+_rules\s*=\s*\[', body, re.M) or re.search(r'^  source\s*=\s*"[^"]*firewall[^"]*"', body, re.M)))


def fw_rules(body):
    """Guest firewall rules of a block, in order: (direction, start, end) of each rule's text in body.
    Provider resource: `rule { … }` blocks. Module: `{ … }` objects of `*_rules = [ … ]` lists."""
    if body.startswith(f'resource "{FW_RESOURCE}"'):
        return [(kv(m.group(), "type") or "in", m.start(), m.end()) for m in re.finditer(r'^  rule \{.*?\n  \}', body, re.S | re.M)]
    out = []
    for sec in re.finditer(r'^  (\w+_rules)\s*=\s*\[(.*?)^  \]', body, re.S | re.M):
        d = "out" if re.search(r"egress|outbound|out_", sec.group(1)) else "in"
        out += [(d, sec.start(2) + r.start(), sec.start(2) + r.end()) for r in re.finditer(r'\{(.*?)\}', sec.group(2), re.S)]
    return out


def fw_state(body):
    """Guest firewall options written at the top of a block: enabled (True/False, None if not literal), policies."""
    m = re.search(r'^  enabled\s*=\s*(true|false)\s*(#.*)?$', body, re.M)
    pol = lambda d: (re.search(rf'^  {d}_policy\s*=\s*"(\w+)"', body, re.M) or [None, None])[1]
    return {"enabled": m.group(1) == "true" if m else None, "input_policy": pol("input"), "output_policy": pol("output")}


RULE_KEYS = ("proto", "dport", "source", "dest", "macro", "comment")


def module_rules(src_dir, repo, call):
    """Rules written in a local firewall module itself (applied to every machine using it). A var. value is taken
    from the module call (a literal top-level argument), else from the variable's literal default; a rule with any
    other reference (local., each., a var. without literal value) is skipped."""
    texts = [(tf.relative_to(repo).as_posix(), tf.read_text(encoding="utf-8")) for tf in sorted(src_dir.glob("*.tf"))] if src_dir.is_dir() else []
    var = {m.group(1): kv(m.group(2), "default") for _, text in texts
           for m in re.finditer(r'^variable "(\w+)" \{(.*?)^\}', text, re.S | re.M)}
    var = {k: (re.search(rf'^  {k}\s*=\s*"([^"]*)"', call, re.M) or [None, v])[1] for k, v in var.items()}
    out = []
    for rel, text in texts:
        for (kind, a, _), line, body in blocks(text):
            if kind == "resource" and a == FW_RESOURCE:
                for d, s, e in fw_rules(body):
                    r = re.sub(r'=(\s*)var\.(\w+)\b', lambda m: f'={m[1]}"{var[m[2]]}"' if var.get(m[2]) is not None else m[0], body[s:e])
                    if not re.search(r'=\s*[a-z_]+\.', r):
                        out.append({"dir": d, "at": [rel, line, None], "line": line + body[:s].count("\n"),
                                    **{k: kv(r, k) for k in RULE_KEYS}})
    return out


def read_tofu(tofu_dir, repo):
    # Only *.tf at the top of tofu_dir: never a state (*.tfstate, may hold secrets) nor a saved plan.
    machines, firewalls, options = [], {}, {}
    for tf in sorted(tofu_dir.glob("*.tf")):
        rel = tf.relative_to(repo).as_posix()
        for (kind, a, b), line, body in blocks(tf.read_text(encoding="utf-8")):
            cid = val(body, "container_id") or val(body, "vm_id")
            if kind == "resource" and a == FW_OPTIONS and cid:
                options[cid] = {**fw_state(body), "options": [rel, line]}
                continue
            if is_firewall(kind, a, body) and cid:
                label = b if kind == "resource" else a
                fw = firewalls.setdefault(cid, {"name": re.sub(r"^(firewall|fw)_", "", label), "node": val(body, "node_name"),
                                                "file": rel, "line": line, "rules": [], "module": kind == "module",
                                                "enabled": None, "input_policy": None, "output_policy": None, "options": None, "common": []})
                if kind == "module":  # a firewall module may take its options as arguments
                    fw.update({k: v for k, v in fw_state(body).items() if v is not None}, options=[rel, line])
                    src = val(body, "source") or ""
                    if src.startswith(("./", "../")):
                        mdir = (tofu_dir / src).resolve()
                        fw["common"] = module_rules(mdir, repo.resolve(), body) if repo.resolve() in mdir.parents else []
                fw["rules"] += [{"dir": d, "at": [rel, line, i], "line": line + body[:s].count("\n"), **{k: kv(body[s:e], k) for k in RULE_KEYS}}
                                for i, (d, s, e) in enumerate(fw_rules(body))]
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
    for cid, o in options.items():
        if cid in firewalls:
            firewalls[cid].update(o)
    return machines, firewalls


def read_inventory(text):
    """groups (all hosts, children included), direct (hosts listed in the group itself), ips."""
    inv = yaml.safe_load(text) or {}
    children = (inv.get("all") or inv).get("children") or {}
    groups, direct, ips = {}, {}, {}

    def walk(name, d):
        d = d or {}
        hosts = list((d.get("hosts") or {}).keys())
        direct[name] = sorted(hosts)
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
    return groups, direct, ips


def read_ansible(cfg, repo):
    groups, direct, ips = read_inventory((repo / cfg["inventory"]).read_text(encoding="utf-8"))
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
    return groups, direct, ips, playbooks, roles


def git_rev(repo):
    try:
        return subprocess.run(["git", "-C", str(repo), "log", "-1", "--format=%h %cs"],
                              capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return ""


def ip_or_none(s):
    try:
        return ipaddress.ip_address(str(s or "").strip())
    except ValueError:
        return None


def nets(addr):
    """Networks of a rule address ("10.0.0.2", "10.0.0.0/24", "a,b"); None: anywhere. Aliases, ipsets: skipped."""
    out = []
    for p in str(addr or "").split(","):
        try:
            out.append(ipaddress.ip_network(p.strip(), strict=False))
        except ValueError:
            pass
    return None if not str(addr or "").strip() or any(n.prefixlen == 0 for n in out) else out


def port_ranges(s):
    """dport "22", "1514,1515", "137:138" as [(lo, hi)]; None: any port (or not literal)."""
    if not s or not re.fullmatch(r"\d+([:-]\d+)?(,\d+([:-]\d+)?)*", s.replace(" ", "")):
        return None
    return [tuple(int(x) for x in (p.replace("-", ":").split(":") * 2)[:2]) for p in s.replace(" ", "").split(",")]


def same_traffic(a, b):
    """Could two rules let the same packets through? Unknown protocol or port (a macro) counts as any."""
    if a.get("proto") and b.get("proto") and a["proto"] != b["proto"]:
        return False
    pa, pb = port_ranges(a.get("dport")), port_ranges(b.get("dport"))
    return pa is None or pb is None or any(x[0] <= y[1] and y[0] <= x[1] for x in pa for y in pb)


def flows(machines, firewalls, ips):
    """One flow per guest firewall rule: src and dst endpoints {k: machine key (one machine), a: address as
    written ("" = anywhere), n: machine keys it covers, wide: a network, not single addresses}."""
    where = {}  # address -> machine key, Tofu first
    for k, ip in [(key(m["name"]), m["ip"]) for m in machines] + [(key(h), ip) for h, ip in ips.items()]:
        if ip_or_none(ip):
            where.setdefault(ip_or_none(ip), k)
    by_id = {str(m["id"]): m for m in machines if m["id"]}
    out = []
    for cid, fw in sorted(firewalls.items()):
        own = key(by_id[cid]["name"]) if cid in by_id else key(fw["name"])
        me = {"k": own, "a": "", "n": [own], "wide": False}
        for common, r in [(False, r) for r in fw["rules"]] + [(True, r) for r in fw["common"]]:
            addr = r["dest"] if r["dir"] == "out" else r["source"]
            ns = nets(addr)
            n = sorted({k for ip, k in where.items() for net in ns or [] if ip in net})
            single = bool(ns) and all(net.num_addresses == 1 for net in ns)
            peer = {"k": n[0] if single and len(ns) == 1 and n else None, "a": addr if ns is not None else "", "n": n, "wide": not single}
            out.append({"owner": own, "dir": r["dir"], "src": me if r["dir"] == "out" else peer, "dst": peer if r["dir"] == "out" else me,
                        **{k: r[k] for k in ("proto", "dport", "macro", "comment")}, "file": r["at"][0], "line": r["line"],
                        "common": common, "half": False})
    return out


def half_open(fl, firewalls, machines, ips):
    """Flows allowed on one side only: an outgoing rule on A to B that no incoming rule on B lets in, or the reverse.
    Only between two single machines, and only where the other side filters that direction."""
    by_id = {str(m["id"]): m for m in machines if m["id"]}
    fw_of = {key(by_id[c]["name"]) if c in by_id else key(fw["name"]): fw for c, fw in firewalls.items()}
    addrs = {}
    for k, ip in [(key(m["name"]), m["ip"]) for m in machines] + [(key(h), ip) for h, ip in ips.items()]:
        if ip_or_none(ip):
            addrs.setdefault(k, set()).add(ip_or_none(ip))
    for f in fl:
        a, b = f["src"]["k"], f["dst"]["k"]
        if not a or not b or a == b:
            continue
        other, need = (b, "in") if f["dir"] == "out" else (a, "out")
        fw = fw_of.get(other)
        if not fw or fw["enabled"] is False:
            continue
        rules = [r for r in fw["rules"] + fw["common"] if r["dir"] == need]
        # Proxmox defaults: input DROP, output ACCEPT. A module's own default is not read: its outgoing rules hint at DROP.
        policy = fw["input_policy"] if need == "in" else fw["output_policy"] or ("DROP" if rules else "ACCEPT")
        if policy == "ACCEPT":
            continue
        mine = addrs.get(f["owner"])
        if mine and not any(same_traffic(r, f) and (nets(r["source" if need == "in" else "dest"]) is None or
                                           any(ip in n for ip in mine for n in nets(r["source" if need == "in" else "dest"])))
                   for r in rules):
            f["half"] = True
            yield f


def drift(cfg, machines, firewalls, groups, ips, playbooks, inv_text, fl=(), cap=None):
    """Inconsistencies between Tofu, the firewalls, the inventory and the playbooks. Each finding:
    {kind, severity (warn|info), machine (page key), file, line, msg (English template), vars}."""
    inv_lines = inv_text.splitlines()
    inv_line = lambda h: next((i + 1 for i, l in enumerate(inv_lines) if re.match(rf"\s+{re.escape(h)}:(\s|$)", l)), 1)
    hosts = {key(h): h for h in ips}
    tofu = {key(m["name"]): m for m in machines}
    by_id = {str(m["id"]): m for m in machines if m["id"]}
    outside = {key(h) for g in (cfg["node_group"], cfg["bare_metal_group"]) for h in groups.get(g, [])}
    got = {}
    for plays in playbooks.values():
        for p in plays:
            for h in p["hosts"]:
                got.setdefault(key(h), set()).update(p["roles"])
    out = []

    def add(kind, sev, machine, file, line, msg, **v):
        out.append({"kind": kind, "severity": sev, "machine": machine, "file": file, "line": line, "msg": msg, "vars": v})

    for k, m in sorted(tofu.items()):
        a, b = ip_or_none(m["ip"]), ip_or_none(ips.get(hosts.get(k)))
        if k not in hosts:
            add("not_in_inventory", "warn", k, m["file"], m["line"], "{name} is created by Tofu but is not in the inventory", name=m["name"])
        elif a and b and a != b:
            add("ip_mismatch", "warn", k, m["file"], m["line"], "{name}: Tofu gives {tofu}, the inventory {inventory}",
                name=m["name"], tofu=str(a), inventory=str(b))
    for k, h in sorted(hosts.items()):
        if k not in tofu and k not in outside:
            add("not_in_tofu", "info", k, cfg["inventory"], inv_line(h), "{name} is in the inventory but no Tofu block creates it", name=h)
        if k not in got:
            add("no_playbook", "info", k, cfg["inventory"], inv_line(h), "{name} is in the inventory but no playbook targets it", name=h)
        missing = [r for r in cfg.get("required_roles") or [] if r not in got.get(k, ())]
        if missing:
            add("required_roles", "warn", k, cfg["inventory"], inv_line(h), "{name} does not get the required roles: {roles}",
                name=h, roles=", ".join(missing))
    for cid, fw in firewalls.items():
        m = by_id.get(cid)
        k, name = (key(m["name"]), m["name"]) if m else (key(fw["name"]), fw["name"])
        if not m and k not in hosts:
            add("firewall_orphan", "warn", k, fw["file"], fw["line"], "Firewall {name} targets id {id}, which matches no machine", name=name, id=cid)
        elif fw["enabled"] is False and fw["rules"]:
            add("firewall_off", "warn", k, *fw["options"], "{name}: the guest firewall is turned off, its rules protect nothing", name=name)
        elif fw["options"] is None and fw["rules"]:
            add("firewall_no_options", "info", k, fw["file"], fw["line"],
                "{name}: rules without firewall options; Proxmox keeps a guest firewall off until it is turned on", name=name)
    for f in half_open(fl, firewalls, machines, ips):
        what = (f["proto"] or f["macro"] or "all") + (f"/{f['dport']}" if f["dport"] else "")
        if f["dir"] == "out":
            add("half_open", "info", f["owner"], f["file"], f["line"], "{src} may send {what} to {dst}, but no rule on {dst} lets it in",
                src=f["src"]["k"], dst=f["dst"]["k"], what=what)
        else:
            add("half_open", "info", f["owner"], f["file"], f["line"], "{dst} lets {what} in from {src}, but no rule on {src} lets it out",
                src=f["src"]["k"], dst=f["dst"]["k"], what=what)
    for n, c in (cap or {}).items():
        for f, what, scale in CAP:
            if c["total"].get(f) is not None and c[f] > c["total"][f]:
                if f == "disk" and c[f] >= 1024:  # as the page shows it: TB of 1024 GB
                    scale, what = 1024, "TB of disk"
                add("over_allocated", "warn", n, "", 0, "{node} gives its guests {used} {what}, more than the {total} declared",
                    node=c["name"], used=f"{round(c[f] / scale, 2):g}", total=f"{round(c['total'][f] / scale, 2):g}", what=what)
    return sorted(out, key=lambda f: (f["severity"] != "warn", f["kind"], f["file"], f["line"]))


# (field, unit in messages, declared unit / Tofu unit): Tofu gives memory in MiB, node_capacity declares it in GiB.
CAP = (("cores", "vCPU", 1), ("memory", "GiB of memory", 1024), ("disk", "GB of disk", 1))


def num(v):
    """A literal whole number as Tofu writes it ("2048", "2048 # note"), else None (a variable, nothing)."""
    m = re.fullmatch(r"(\d+)\s*(#.*)?", str(v if v is not None else "").strip())
    return int(m.group(1)) if m else None


def capacity(machines, declared):
    """Per node (key): sums of the vCPU, memory and disk Tofu gives its guests; unknown: guests whose value is not
    a literal number; total: the node's capacity from the settings (node_capacity, memory in GiB), in Tofu's units
    (memory in MiB), {} when not declared."""
    out = {}
    blank = lambda n: {"name": n, "guests": 0, **{f: 0 for f, *_ in CAP}, "unknown": {f: [] for f, *_ in CAP}, "total": {}}
    for m in machines:
        if m["node"]:
            c = out.setdefault(key(m["node"]), blank(m["node"]))
            c["guests"] += 1
            for f, *_ in CAP:
                v = num(m[f])
                if v is None:
                    c["unknown"][f].append(m["name"])
                else:
                    c[f] += v
    for n, tot in (declared or {}).items():
        c = out.setdefault(key(n), blank(n))
        c["total"] = {f: num(tot.get(f)) * k for f, _, k in CAP if isinstance(tot, dict) and num(tot.get(f))}
    return dict(sorted(out.items()))


def merge(data):
    """One entry per machine, merged from Tofu, the firewalls and the inventory, as the page shows them."""
    hosts = {key(h): ip for h, ip in data["ips"].items()}
    new = lambda k, name: {"key": k, "name": name, "host": None, "node": None, "id": None, "ip": "", "tofu": None, "firewall": None}
    M = {}
    for m in data["tofu"]:
        k = key(m["name"])
        M[k] = {**new(k, m["name"]), "node": m["node"] and key(m["node"]), "id": m["id"], "ip": m["ip"] or hosts.get(k) or "",
                "tofu": {f: m[f] for f in ("kind", "address", "cores", "memory", "disk", "file", "line")}}
    by_id = {str(x["id"]): x for x in M.values() if x["id"] is not None}
    for cid, fw in data["firewalls"].items():
        k = key(fw["name"])
        x = by_id.get(cid) or M.get(k) or M.setdefault(k, new(k, fw["name"]))
        x["firewall"] = cid
        x["id"] = x["id"] if x["id"] is not None else int(cid) if cid.isdigit() else None
        x["node"] = x["node"] or (fw["node"] and key(fw["node"]))
    for h, ip in data["ips"].items():
        x = M.setdefault(key(h), new(key(h), h))
        x["ip"], x["host"] = x["ip"] or ip, h
    roles, pbs, groups = {}, {}, {}
    for pb, plays in data["playbooks"].items():
        for p in plays:
            for h in p["hosts"]:
                pbs.setdefault(key(h), set()).add(pb)
                roles.setdefault(key(h), set()).update(p["roles"])
    for g, hs in data["groups"].items():
        for h in hs:
            groups.setdefault(key(h), []).append(g)
    phys = {key(h) for h in data["nodes"] + data["bare"]}
    for k, x in M.items():
        x.update(phys=k in phys, groups=groups.get(k, []), roles=sorted(roles.get(k, ())), playbooks=sorted(pbs.get(k, ())))
    return list(M.values())


# What --json prints and the page's "Download JSON" gives: what the page shows, never a file's contents beyond it.
EXPORT = ("title", "rev", "machines", "capacity", "firewalls", "roles", "playbooks", "groups", "findings", "flows")


def collect(cfg, repo):
    machines, firewalls = read_tofu(repo / cfg["tofu_dir"], repo)
    groups, direct, ips, playbooks, roles = read_ansible(cfg, repo)
    fl = flows(machines, firewalls, ips)
    cap = capacity(machines, cfg.get("node_capacity"))
    findings = drift(cfg, machines, firewalls, groups, ips, playbooks, (repo / cfg["inventory"]).read_text(encoding="utf-8"), fl, cap)
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
        "tofu": machines, "firewalls": firewalls, "groups": groups, "direct": direct, "ips": ips,
        "playbooks": playbooks, "roles": roles, "findings": findings, "flows": fl, "capacity": cap, "server": None,
    }
    data["machines"] = merge(data)
    return data


def collect_empty(cfg):
    return {"title": cfg["title"], "subtitle": cfg["subtitle"], "lang": cfg["lang"], "rev": "", "workflow": {}, "note": None,
            "playbook_prefix": "", "generic_playbooks": [], "links": {}, "paths": {"inventory": "", "playbooks": "", "roles": ""},
            "nodes": [], "bare": [], "tofu": [], "firewalls": {}, "groups": {}, "direct": {}, "ips": {}, "playbooks": {}, "roles": {}, "findings": [], "flows": [], "capacity": {}, "machines": [], "server": None}


def favicon():
    """PNG icon embedded in page.html, also served at /favicon.ico (Safari asks for it and skips SVG icons)."""
    m = re.search(r"data:image/png;base64,([A-Za-z0-9+/=]+)", (HERE / "page.html").read_text(encoding="utf-8"))
    return base64.b64decode(m.group(1))


def render(data):
    page = (HERE / "page.html").read_text(encoding="utf-8")
    blob = json.dumps(data, ensure_ascii=False).replace("</", "<\\u002f")
    return page.replace("/*DATA*/null", blob).replace("<title>Cairn IaC</title>", f"<title>{escape(data['title'])}</title>")


def load_config(path):
    raw = json.loads(path.read_text(encoding="utf-8")) if path else {}
    cfg = {**DEFAULTS, **SERVER, **raw}
    for k in ("git", "firewall_lists"):
        cfg[k] = {**DEFAULTS[k], **(raw.get(k) or {})}
    cfg["base"] = path.parent if path else pathlib.Path.cwd()
    return cfg


def build(cfg_path, out_path):
    cfg = load_config(cfg_path)
    data = collect(cfg, (cfg["base"] / cfg["repo"]).resolve())
    out_path.write_text(render(data), encoding="utf-8", newline="\n")
    print(f"cairn-iac: {out_path} ({len(data['tofu'])} Tofu machines, {len(data['firewalls'])} firewalls, "
          f"{len(data['ips'])} inventory hosts, {len(data['playbooks'])} playbooks, {len(data['roles'])} roles, "
          f"{len(data['findings'])} drift findings)")


def dump(cfg_path):
    """The collected model as JSON (machines merged, capacity, firewalls, roles, findings, flows)."""
    cfg = load_config(cfg_path)
    data = collect(cfg, (cfg["base"] / cfg["repo"]).resolve())
    print(json.dumps({k: data[k] for k in EXPORT}, ensure_ascii=False, indent=2))


def check(cfg_path, as_json):
    """Drift findings on stdout; exit status 1 if one is a warning (for CI)."""
    cfg = load_config(cfg_path)
    findings = collect(cfg, (cfg["base"] / cfg["repo"]).resolve())["findings"]
    if as_json:
        print(json.dumps(findings, ensure_ascii=False, indent=2))
    else:
        for f in findings:
            where = f"{f['file']}:{f['line']}" if f["file"] else "node_capacity"
            print(f"{f['severity']:<5} {f['kind']:<19} {where}  {f['msg'].format(**f['vars'])}")
        n = sum(f["severity"] == "warn" for f in findings)
        print(f"cairn-iac: {n} warnings, {len(findings) - n} notes", file=sys.stderr)
    return 1 if any(f["severity"] == "warn" for f in findings) else 0


def escape(s):
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


# ---------- edits: text-level changes on the repo files, checked by parsing the result again ----------

class Refused(Exception):
    """An edit or request refused; args: an English message template (translated by the page) and its values."""
    def __init__(self, msg, **v):
        super().__init__(msg)
        self.msg, self.v = msg, v


NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")
FIELDS = {"cores": ("cores",), "memory": ("memory", "dedicated"), "disk": ("disk_size", "size")}
LIMITS = {"cores": (1, 512), "memory": (16, 4 << 20), "disk": (1, 1 << 17)}


def name_ok(s, what):
    if not isinstance(s, str) or not NAME.match(s):
        raise Refused("Invalid {what}: {value}", what=what, value=str(s)[:64])
    return s


def edit_block(text, line, fn):
    """Replace the top-level block starting at `line` by fn(body)."""
    lines = text.splitlines(keepends=True)
    for _, l, body in blocks(text):
        if l == line:
            nl = "\r\n" if lines[line - 1].endswith("\r\n") else "\n"
            lines[line - 1:line - 1 + body.count("\n") + 1] = [fn(body).replace("\n", nl) + nl]
            return "".join(lines)
    raise Refused("No block at line {line}: the file changed, reload the page", line=line)


def set_resources(body, values):
    done = []
    for f, v in values.items():
        if v in (None, ""):
            continue
        try:
            v = int(v)
        except (TypeError, ValueError):
            raise Refused("Invalid {what}: {value}", what=f, value=str(v)[:20])
        lo, hi = LIMITS[f]
        if not lo <= v <= hi:
            raise Refused("{what} must be between {lo} and {hi}", what=f, lo=lo, hi=hi)
        for k in FIELDS[f]:
            m = re.search(rf'^(\s*{k}\s*=\s*)("?)(\d+)\2[ \t]*(#.*)?$', body, re.M)
            if m:
                break
        else:
            raise Refused("No literal value for {what} in the block (variable?): edit it in the file", what=f)
        old = int(m.group(3))
        if f == "disk" and v < old:
            raise Refused("A disk cannot shrink ({old} → {new} GB)", old=old, new=v)
        if v != old:
            body = body[:m.start(3)] + str(v) + body[m.end(3):]
            done.append(f"{f} {old} -> {v}")
    return body, done


def check_rule(r):
    d, proto, port, addr, com = (str(r.get(k) or "").strip() for k in ("dir", "proto", "dport", "addr", "comment"))
    if d not in ("in", "out"):
        raise Refused("Invalid {what}: {value}", what="direction", value=d)
    if proto not in ("tcp", "udp", "icmp"):
        raise Refused("Invalid {what}: {value}", what="protocol", value=proto)
    if proto == "icmp":
        port = ""
    elif not re.fullmatch(r"\d{1,5}([:-]\d{1,5})?(,\d{1,5}([:-]\d{1,5})?)*", port) or any(int(p) > 65535 for p in re.split(r"[:,-]", port)):
        raise Refused("Invalid {what}: {value}", what="port", value=port[:20])
    if addr:
        try:
            addr = str(ipaddress.ip_network(addr, strict=False)) if "/" in addr else str(ipaddress.ip_address(addr))
        except ValueError:
            raise Refused("Invalid {what}: {value}", what="address", value=addr[:50])
    if not com or len(com) > 200 or re.search(r'["\\\r\n]|\$\{|%\{', com):
        raise Refused("The comment is required, 200 characters at most, without quotes or backslashes")
    return d, proto, port, addr, com


def fw_add(body, rule, lists):
    d, proto, port, addr, com = check_rule(rule)
    fields = [("comment", com), ("proto", proto), ("dport", port), ("dest" if d == "out" else "source", addr)]
    fields = [(k, v) for k, v in fields if v]
    head = body[:body.rindex("}")]
    if body.startswith(f'resource "{FW_RESOURCE}"'):
        fields = [("type", d), ("action", "ACCEPT")] + fields
        w = max(len(k) for k, _ in fields)
        return head + "  rule {\n" + "".join(f'    {k.ljust(w)} = "{v}"\n' for k, v in fields) + "  }\n}"
    name = lists.get(d) or ""
    if not re.fullmatch(r"\w+_rules", name):
        raise Refused("Set the firewall list for {dir} rules in Settings", dir=d)
    obj = "{ " + ", ".join(f'{k} = "{v}"' for k, v in fields) + " },\n"
    m = re.search(rf'^  {name}\s*=\s*\[.*?^(  \])', body, re.S | re.M)
    if m:
        return body[:m.start(1)] + "    " + obj + body[m.start(1):]
    if re.search(rf'^  {name}\s*=', body, re.M):
        raise Refused("The list {name} is not written one rule per line: edit it in the file", name=name)
    return head + ("" if head.endswith("\n\n") else "\n") + f"  {name} = [\n    {obj}  ]\n}}"


def fw_del(body, i):
    rules = fw_rules(body)
    if not isinstance(i, int) or not 0 <= i < len(rules):
        raise Refused("No such rule: the file changed, reload the page")
    _, s, e = rules[i]
    ls = body.rfind("\n", 0, s) + 1
    le = body.find("\n", e)
    le = len(body) if le < 0 else le
    if body[ls:s].strip() or not re.fullmatch(r",?[ \t]*(#.*)?", body[e:le]):
        raise Refused("This rule shares its line with another: edit it in the file")
    return body[:ls] + body[le + 1:]


def indent(l):
    return len(l) - len(l.lstrip(" "))


def yaml_key(l):
    m = re.match(r"\s*([^\s#:][^:#]*?):(\s|$)", l)
    return m.group(1) if m else None


def sub_block(lines, i):
    """End (exclusive) of the YAML mapping entry at line i: following lines indented deeper, or blank."""
    j, ind = i + 1, indent(lines[i])
    while j < len(lines) and (not lines[j].strip() or indent(lines[j]) > ind):
        j += 1
    while j > i + 1 and not lines[j - 1].strip():
        j -= 1
    return j


def find_group(lines, group):
    for i, l in enumerate(lines):
        if yaml_key(l) == group and indent(l) > 0 and re.fullmatch(r"\s*[^:]+:\s*(#.*)?\s*", l):
            for j in range(i - 1, -1, -1):  # parent key must be `children`
                p = lines[j]
                if p.strip() and not p.lstrip().startswith("#") and indent(p) < indent(l):
                    if yaml_key(p) == "children":
                        return i
                    break
    raise Refused("Group {group} not found in the inventory, or not written as a block", group=group)


def hosts_line(lines, gi):
    end = sub_block(lines, gi)
    kids = [j for j in range(gi + 1, end) if lines[j].strip() and not lines[j].lstrip().startswith("#")]
    ci = indent(lines[kids[0]]) if kids else indent(lines[gi]) + 2
    for j in kids:
        if indent(lines[j]) == ci and yaml_key(lines[j]) == "hosts":
            if not re.fullmatch(r"\s*hosts:\s*(#.*)?\s*", lines[j]):
                raise Refused("The hosts of {group} are not written as a block: edit it in the file", group=yaml_key(lines[gi]))
            return j, ci
    return None, ci


def group_add(text, group, host, ip=""):
    name_ok(group, "group"), name_ok(host, "host")
    groups, direct, ips = read_inventory(text)
    if host in direct.get(group, []):
        raise Refused("{host} is already in {group}", host=host, group=group)
    lines = text.splitlines(keepends=True)
    nl = "\r\n" if lines and lines[0].endswith("\r\n") else "\n"
    gi = find_group(lines, group)
    hi, ci = hosts_line(lines, gi)
    entry = []
    if hi is None:
        at, hind = gi + 1, ci + 2
        entry.append(" " * ci + "hosts:" + nl)
    else:
        end = sub_block(lines, hi)
        kids = [j for j in range(hi + 1, end) if lines[j].strip() and not lines[j].lstrip().startswith("#")]
        at, hind = end, indent(lines[kids[0]]) if kids else ci + 2
    if host in ips:
        entry.append(" " * hind + host + ":" + nl)
    else:  # a machine new to the inventory: give it its address
        ip = str(ipaddress.ip_address(ip)) if ip else ""
        entry.append(" " * hind + host + ":" + nl + (" " * (hind + 2) + f"ansible_host: {ip}" + nl if ip else ""))
    if at > 0 and not lines[at - 1].endswith("\n"):
        lines[at - 1] += nl
    lines[at:at] = entry
    out = "".join(lines)
    if host not in read_inventory(out)[1].get(group, []):
        raise Refused("The edit did not give the expected inventory: edit it in the file")
    return out


def group_del(text, group, host):
    name_ok(group, "group"), name_ok(host, "host")
    lines = text.splitlines(keepends=True)
    gi = find_group(lines, group)
    hi, _ = hosts_line(lines, gi)
    if hi is not None:
        for j in range(hi + 1, sub_block(lines, hi)):
            if yaml_key(lines[j]) == host and re.fullmatch(r"\s*[^:]+:\s*(null|~)?\s*(#.*)?\s*", lines[j]):
                if sub_block(lines, j) > j + 1:
                    raise Refused("{host} has variables in {group}: edit it in the file", host=host, group=group)
                out = "".join(lines[:j] + lines[j + 1:])
                if host in read_inventory(out)[1].get(group, []):
                    break
                return out
    raise Refused("{host} is not listed directly in {group}", host=host, group=group)


def play_spans(lines, plays):
    """(play, first line, end line exclusive) of each top-level play, 0-based; [] when the `- ` items and the parsed
    plays do not line up."""
    starts = [i for i, l in enumerate(lines) if re.match(r"-(\s|$)", l)]
    if not isinstance(plays, list) or len(starts) != len(plays):
        return []
    return [(p, s, e) for p, s, e in zip(plays, starts, starts[1:] + [len(lines)])]


def role_into_play(text, plays, host, role):
    """The role appended to the block-style `roles:` list of the first play whose hosts is exactly `host`; None if none."""
    lines = text.splitlines(keepends=True)
    for n, (p, s, e) in enumerate(play_spans(lines, plays)):
        if not (isinstance(p, dict) and str(p.get("hosts", "")).strip() == host and isinstance(p.get("roles"), list) and p["roles"]):
            continue
        ki = len(re.match(r"-\s*", lines[s]).group())  # indent of the play's keys
        ri = next((j for j in range(s + 1, e) if indent(lines[j]) == ki and re.fullmatch(r"\s*roles:\s*(#.*)?\s*", lines[j])), None)
        if ri is None:
            return None
        j, items = ri + 1, []
        while j < e and (not lines[j].strip() or lines[j].lstrip().startswith("#") or indent(lines[j]) > ki
                         or (indent(lines[j]) == ki and lines[j].lstrip().startswith("- "))):
            if lines[j].lstrip().startswith("- ") and (not items or indent(lines[j]) == indent(lines[items[0]])):
                items.append(j)
            j += 1
        while j > ri + 1 and (not lines[j - 1].strip() or lines[j - 1].lstrip().startswith("#")):
            j -= 1
        if not items:
            return None
        nl = "\r\n" if lines[ri].endswith("\r\n") else "\n"
        if not lines[j - 1].endswith("\n"):
            lines[j - 1] += nl
        lines.insert(j, " " * indent(lines[items[0]]) + f"- {role}" + nl)
        return "".join(lines), n
    return None


def role_add(text, host, role):
    """The role for the host: into a play that targets exactly that host, else a new play at the end."""
    name_ok(host, "host"), name_ok(role, "role")
    plays = yaml.safe_load(text) or []
    merged = role_into_play(text, plays, host, role) if isinstance(plays, list) else None
    if merged:
        out, n = merged
        new = yaml.safe_load(out)
        if isinstance(new, list) and len(new) == len(plays) and new[n].get("roles") == plays[n]["roles"] + [role] \
                and all(a == b for i, (a, b) in enumerate(zip(new, plays)) if i != n):
            return out
    out = text + ("" if not text or text.endswith("\n") else "\n") + f"\n- name: {role} ({host})\n  hosts: {host}\n  roles:\n    - {role}\n"
    new = yaml.safe_load(out)
    if not isinstance(new, list) or new[-1].get("roles") != [role]:
        raise Refused("The edit did not give the expected playbook: edit it in the file")
    return out


def apply(op, cfg, repo):
    """(repo-relative file, old text, new text, commit message) for one requested edit."""
    o = op.get("op")
    if o in ("resources", "fw_add", "fw_del"):
        tofu = (repo / cfg["tofu_dir"]).resolve()
        rel = str(op.get("file") or "")
        path = (repo / rel).resolve()
        if path.parent != tofu or path.suffix != ".tf" or not path.is_file():
            raise Refused("Unknown file: {file}", file=rel[:100])
        line = op.get("line")
        if not isinstance(line, int):
            raise Refused("No block at line {line}: the file changed, reload the page", line=line)
        old = path.read_text(encoding="utf-8")
        label = str(op.get("name") or "")[:64]
        if o == "resources":
            done = []
            def fn(body):
                b, d = set_resources(body, {k: op.get(k) for k in FIELDS})
                done.extend(d)
                return b
            new = edit_block(old, line, fn)
            msg = f"{label}: {', '.join(done)}"
        elif o == "fw_add":
            new = edit_block(old, line, lambda b: fw_add(b, op.get("rule") or {}, cfg["firewall_lists"]))
            r = op.get("rule") or {}
            msg = f"{label}: firewall, allow {r.get('dir')} {r.get('proto')}/{r.get('dport') or '*'} ({r.get('comment')})"
        else:
            new = edit_block(old, line, lambda b: fw_del(b, op.get("index")))
            msg = f"{label}: firewall, remove rule ({str(op.get('comment') or '')[:80]})"
        # The edited block must still parse, with one rule more (in the asked direction) or less.
        before = {l: [d for d, _, _ in fw_rules(b)] for _, l, b in blocks(old)}
        after = {l: [d for d, _, _ in fw_rules(b)] for _, l, b in blocks(new)}
        d = (op.get("rule") or {}).get("dir")
        ok = {"resources": lambda a, b: a == b, "fw_del": lambda a, b: len(a) == len(b) - 1,
              "fw_add": lambda a, b: a.count(d) == b.count(d) + 1 and len(a) == len(b) + 1}[o]
        if len(before) != len(after) or line not in after or not ok(after[line], before.get(line, [])):
            raise Refused("The edit did not give the expected file: edit it in the file")
        return rel, old, new, msg
    if o in ("group_add", "group_del"):
        rel, path = cfg["inventory"], repo / cfg["inventory"]
        old = path.read_text(encoding="utf-8")
        host, group = op.get("host"), op.get("group")
        if o == "group_add":
            return rel, old, group_add(old, group, host, op.get("ip") or ""), f"inventory: add {host} to {group}"
        return rel, old, group_del(old, group, host), f"inventory: remove {host} from {group}"
    if o == "role_add":
        pb, role, host = op.get("playbook"), op.get("role"), op.get("host")
        name_ok(pb, "playbook"), name_ok(role, "role")
        path = repo / cfg["playbooks"] / f"{pb}.yml"
        if not path.is_file():
            raise Refused("Unknown file: {file}", file=f"{pb}.yml")
        if not (repo / cfg["roles"] / role).is_dir():
            raise Refused("Unknown role: {role}", role=role)
        old = path.read_text(encoding="utf-8")
        return (pathlib.PurePosixPath(cfg["playbooks"]) / f"{pb}.yml").as_posix(), old, role_add(old, host, role), f"{pb}: apply {role} to {host}"
    raise Refused("Unknown edit: {op}", op=str(o)[:20])


def span(repo, rel, line):
    """First and last line of the top-level block starting at `line` in a repo file, None if gone."""
    try:
        text = (repo / rel).read_text(encoding="utf-8")
    except OSError:
        return None
    return next(((l, l + body.count("\n")) for _, l, body in blocks(text) if l == line), None)


# Fields split by 0x02/0x03, not 0x1e/0x1f: Python treats those as whitespace and line breaks.
LOG = "--format=%x02%H%x03%ct%x03%cs%x03%an%x03%s"


def history(git, repo, data, m, cfg, cap=15):
    """Latest commits touching a machine: its Tofu block, firewall block(s) and inventory entries (git log -L), and
    inventory or playbook changes whose lines name its host (git log -G). git(*args) runs git in the repo, returns stdout.
    A commit on the shallow clone's boundary is not listed: `truncated`, history not fetched before `since`."""
    queries = []
    tf = next((x for x in data["tofu"] if m["tofu"] and x["address"] == m["tofu"]["address"]), None)
    if tf:
        queries.append(("tofu", ["-L", f"{tf['line']},{tf['line'] + tf['code'].count(chr(10))}:{tf['file']}"]))
    fw = data["firewalls"].get(m["firewall"]) if m["firewall"] is not None else None
    for at in {(fw["file"], fw["line"]), tuple(fw["options"] or (fw["file"], fw["line"]))} if fw else ():
        sp = span(repo, *at)
        if sp:
            queries.append(("firewall", ["-L", f"{sp[0]},{sp[1]}:{at[0]}"]))
    if m["host"]:
        # its entries in the inventory (the host key and its variables), then any line naming it (membership, plays)
        lines = (repo / cfg["inventory"]).read_text(encoding="utf-8").splitlines()
        for i, l in enumerate(lines):
            if yaml_key(l) == m["host"] and indent(l) > 0:
                queries.append(("inventory", ["-L", f"{i + 1},{sub_block(lines, i)}:{cfg['inventory']}"]))
        # the plays aimed at exactly that host (a role added to one changes no line naming it)
        for f in sorted((repo / cfg["playbooks"]).glob("*.yml")):
            lines = f.read_text(encoding="utf-8").splitlines(keepends=True)
            try:
                plays = yaml.safe_load("".join(lines))
            except yaml.YAMLError:
                continue
            for p, s, e in play_spans(lines, plays):
                while e > s + 1 and not lines[e - 1].strip():
                    e -= 1
                if isinstance(p, dict) and str(p.get("hosts", "")).strip() == m["host"]:
                    queries.append(("playbook", ["-L", f"{s + 1},{e}:{f.relative_to(repo).as_posix()}"]))
        word = "[^A-Za-z0-9_.-]"
        queries.append(("inventory", ["-G", f"(^|{word}){m['host'].replace('.', '[.]')}($|{word})", "--",
                                      cfg["inventory"], cfg["playbooks"]]))
    shallow = (repo / git("rev-parse", "--git-path", "shallow")).resolve()
    cut = set(shallow.read_text().split()) if shallow.is_file() else set()
    found = {}
    for what, args in queries:
        for l in git("log", "-s", "-n", str(cap), LOG, *args).splitlines():
            if l.startswith("\x02"):
                sha, ct, date, author, subject = l[1:].split("\x03", 4)
                c = found.setdefault(sha, {"sha": sha, "short": sha[:8], "time": int(ct), "date": date, "author": author,
                                           "subject": subject[:200], "what": [], "cut": sha in cut})
                if what not in c["what"]:
                    c["what"].append(what)
    commits = sorted(found.values(), key=lambda c: -c["time"])[:cap]
    # The boundary commit holds every line older than the clone: shown as the cut, not as a change.
    edge = next((c for c in commits if c.pop("cut")), None)
    return {"commits": [c for c in commits if c["sha"] != (edge or {}).get("sha")], "truncated": edge is not None,
            "since": edge and edge["date"], "shallow": bool(cut), "depth": depth(cfg["git"])}


def depth(g):
    """Clone depth from the git settings (an int, or a string from an old settings file)."""
    return int(g.get("depth") or 0) or DEFAULTS["git"]["depth"]


def agit_push(branch, topic, text, who):
    """git push arguments opening a Forgejo/Gitea AGit pull request: title = the commit subject, description = who
    proposed it and the commit body. Push options cannot hold a newline: the description is one line."""
    subject, _, body = text.strip().partition("\n")
    desc = " ".join(f"Proposed by {who} from Cairn IaC. {body}".split())[:2000]
    return ["push", "origin", f"HEAD:refs/for/{branch}", "-o", f"topic={topic}", "-o", f"title={subject.strip()[:200]}",
            "-o", f"description={desc}"]


# ---------- server: the page, edits committed and pushed to Git, Settings ----------

class App:
    def __init__(self, cfg):
        self.cfg = cfg
        self.data = (cfg["base"] / cfg["data_dir"]).resolve()
        self.data.mkdir(parents=True, exist_ok=True)
        self.settings_file = self.data / "settings.json"
        if not self.settings_file.exists():
            self.save_settings({k: cfg[k] for k in SETTINGS})
        self.key = (cfg["base"] / cfg["ssh_key"]).resolve() if cfg["ssh_key"] else self.data / "id_ed25519"
        if not cfg["ssh_key"] and not self.key.exists() and shutil.which("ssh-keygen"):
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "cairn-iac", "-f", str(self.key)], check=True)
        self.lock = threading.Lock()  # ponytail: one lock for sync, edits and page builds; fine for a handful of users
        self.synced, self.sync_error, self.cache, self.hist = 0.0, "", (None, None), {}
        self.proxies = [ipaddress.ip_network(p, strict=False) for p in cfg["trusted_proxies"]]

    def settings(self):
        s = json.loads(self.settings_file.read_text(encoding="utf-8"))
        out = {**DEFAULTS, **{k: s[k] for k in SETTINGS if k in s}}
        for k in ("git", "firewall_lists"):
            out[k] = {**DEFAULTS[k], **(s.get(k) or {})}
        return out

    def save_settings(self, s):
        tmp = self.settings_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(s, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(tmp, self.settings_file)

    def repo(self, s):
        return self.data / "repo" if s["git"]["url"] else (self.cfg["base"] / self.cfg["repo"]).resolve()

    def git(self, repo, *args, timeout=60, output=False):
        env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
        if self.key.exists():
            env["GIT_SSH_COMMAND"] = (f"ssh -i {self.key} -o IdentitiesOnly=yes -o BatchMode=yes "
                                      f"-o StrictHostKeyChecking=accept-new -o UserKnownHostsFile={self.data / 'known_hosts'}")
        r = subprocess.run(["git", "-C", str(repo), *args], env=env, capture_output=True, encoding="utf-8", errors="replace", timeout=timeout)
        if r.returncode:
            raise Refused("git {cmd}: {err}", cmd=args[0], err=(r.stderr or r.stdout).strip()[-400:])
        return (r.stdout + r.stderr) if output else r.stdout.strip()

    def sync(self, s, force=False):
        """Own clone of the remote, reset to the remote branch at most every 30 s (or now when forced)."""
        g = s["git"]
        if not g["url"] or (not force and time.time() - self.synced < 30):
            return
        repo = self.data / "repo"
        try:
            if not (repo / ".git").exists():
                shutil.rmtree(repo, ignore_errors=True)
                self.git(self.data, "clone", "-q", "--depth", str(depth(g)), "--branch", g["branch"], "--", g["url"], str(repo), timeout=300)
            else:
                self.git(repo, "remote", "set-url", "origin", g["url"])
                self.git(repo, "fetch", "-q", "--depth", str(depth(g)), "origin", g["branch"], timeout=120)
                self.git(repo, "reset", "-q", "--hard", "FETCH_HEAD")
                self.git(repo, "clean", "-qfd")
            self.synced, self.sync_error = time.time(), ""
        except (Refused, subprocess.TimeoutExpired) as e:
            self.synced, self.sync_error = time.time(), getattr(e, "v", {}).get("err") or str(e)

    def head(self, repo):
        try:
            return self.git(repo, "rev-parse", "HEAD")
        except (Refused, OSError):
            return ""

    def user(self, h):
        """User name, or None when the request does not come the way the config allows."""
        peer = ipaddress.ip_address(h.client_address[0])
        if not self.proxies:
            return "local" if peer.is_loopback else None
        if not any(peer in n for n in self.proxies):
            return None
        user = h.headers.get(self.cfg["user_header"], "").strip()
        groups = [g.strip() for g in h.headers.get(self.cfg["groups_header"], "").split(",")]
        ok = not self.cfg["require_groups"] or any(g in self.cfg["require_groups"] for g in groups)
        return user if user and ok and "\n" not in user else None

    def model(self, s, repo, rev):
        """(stamp, collected model) at this commit and these settings; stamp None on error (caller holds the lock)."""
        stamp = (rev, self.settings_file.stat().st_mtime)
        if self.cache[0] != stamp or not rev:
            try:
                self.cache = (stamp, collect(s, repo))
            except (OSError, yaml.YAMLError) as e:  # no clone yet, wrong paths: the Settings page stays reachable
                self.cache = (None, {**collect_empty(s), "error": str(e)})
        return self.cache

    def page(self, user):
        with self.lock:
            s = self.settings()
            self.sync(s)
            repo = self.repo(s)
            rev = self.head(repo)
            data = dict(self.model(s, repo, rev)[1])
        pub = pathlib.Path(f"{self.key}.pub")
        data["server"] = {
            "user": user, "rev": rev, "edit": not self.cfg["read_only"], "settings": {k: s[k] for k in SETTINGS},
            "key": pub.read_text().strip() if pub.exists() else "", "sync_error": self.sync_error,
            "synced": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.synced)) if self.synced else "",
        }
        return render(data)

    def history(self, k):
        """A machine's latest commits (see history()), cached per commit and settings."""
        with self.lock:
            s = self.settings()
            self.sync(s)
            repo = self.repo(s)
            stamp, data = self.model(s, repo, self.head(repo))
            if not stamp:
                raise Refused("Cannot read the repository: {err}", err=data.get("error", ""))
            if (stamp, k) not in self.hist:
                m = next((x for x in data["machines"] if x["key"] == k), None)
                if not m:
                    raise Refused("Unknown machine: {name}", name=str(k)[:64])
                self.hist = {x: v for x, v in self.hist.items() if x[0] == stamp}
                self.hist[stamp, k] = history(lambda *a: self.git(repo, *a), repo, data, m, s)
            return self.hist[stamp, k]

    def author(self, h, user):
        """(name, email) of the signed-in user, from the proxy headers, else made from the user name."""
        name = h.headers.get(self.cfg["name_header"], "").strip() if self.proxies else ""
        mail = h.headers.get(self.cfg["email_header"], "").strip() if self.proxies else ""
        name = name if name and not re.search(r"[<>\n]", name) else user
        mail = mail if re.fullmatch(r"[^<>\s@]+@[^<>\s@]+", mail) else f"{user}@cairn-iac"
        return name, mail

    def edit(self, h, user, op, commit):
        if self.cfg["read_only"]:
            raise Refused("Editing is turned off on this server")
        with self.lock:
            s = self.settings()
            self.sync(s, force=commit)
            repo = self.repo(s)
            if op.get("rev") != self.head(repo):
                raise Refused("The repository moved since the page was loaded: reload the page")
            rel, old, new, msg = apply(op, s, repo)
            if new == old:
                raise Refused("Nothing changes")
            diff = "".join(difflib.unified_diff(old.splitlines(True), new.splitlines(True), f"a/{rel}", f"b/{rel}"))
            msg = s["git"]["commit_prefix"] + msg
            if not commit:
                return {"ok": True, "file": rel, "diff": diff, "message": msg}
            text = str(op.get("message") or msg).strip()
            if not text or len(text) > 2000 or "\0" in text:
                raise Refused("Invalid {what}: {value}", what="message", value=text[:40])
            (repo / rel).write_bytes(new.encode("utf-8"))
            g = s["git"]
            try:
                self.git(repo, "add", "--", rel)
                self.git(repo, "-c", f"user.name={g['name']}", "-c", f"user.email={g['email']}",
                         "commit", "-q", "--author", "{} <{}>".format(*self.author(h, user)), "-m", text)
                sha = self.git(repo, "rev-parse", "--short", "HEAD")
                mode, ref, link = g.get("mode") or "push", g["branch"], ""
                if g["url"] and g["push"]:
                    topic = "cairn-iac/" + re.sub(r"[^A-Za-z0-9_.-]", "-", user)[:40] + time.strftime("-%Y%m%d-%H%M%S")
                    if mode == "agit":
                        name = self.author(h, user)[0]
                        out = self.git(repo, *agit_push(g["branch"], topic, text, name if name == user else f"{name} ({user})"),
                                       timeout=120, output=True)
                        ref = topic
                    elif mode == "branch":
                        out = self.git(repo, "push", "origin", f"HEAD:refs/heads/{topic}", timeout=120, output=True)
                        ref = topic
                    else:
                        out = self.git(repo, "push", "origin", f"HEAD:refs/heads/{g['branch']}", timeout=120, output=True)
                    # The Git server often prints the pull request (or "create one") link.
                    m = re.search(r"https?://\S+", out)
                    link = m.group(0) if m and mode != "push" else ""
                    if mode != "push":  # the edit waits in its pull request: back to the branch as it is
                        self.sync(s, force=True)
            except (Refused, subprocess.TimeoutExpired):
                # Nothing half done stays: back to the remote state (or the last commit, without a remote).
                if g["url"]:
                    self.sync(s, force=True)
                else:
                    self.git(repo, "checkout", "-q", "--", rel)
                raise
            return {"ok": True, "commit": sha, "pushed": bool(g["url"] and g["push"]), "mode": mode, "ref": ref, "link": link}

    def put_settings(self, new):
        if self.cfg["read_only"]:
            raise Refused("Editing is turned off on this server")
        cur = self.settings()
        out = {}
        for k in SETTINGS:
            v = new.get(k, cur[k])
            if k == "generic_playbooks":
                v = [name_ok(x, "playbook") for x in (v or [])]
            elif k == "required_roles":
                v = [name_ok(x, "role") for x in (v or [])]
            elif k == "node_capacity":
                ok = lambda x: isinstance(x, int) and not isinstance(x, bool) and 0 < x < 1 << 40
                if not isinstance(v, dict) or not all(isinstance(c, dict) and all(f in FIELDS and ok(x) for f, x in c.items()) for c in v.values()):
                    raise Refused("Invalid {what}: {value}", what=k, value=json.dumps(v)[:60])
                v = {name_ok(n, "node"): c for n, c in v.items() if c}
            elif k in ("git", "firewall_lists", "workflow", "links", "note"):
                if v is not None and not isinstance(v, dict):
                    raise Refused("Invalid {what}: {value}", what=k, value=type(v).__name__)
                v = {a: (b if isinstance(b, bool) else str(b)[:500]) for a, b in (v or {}).items()} if v is not None else None
            else:
                v = str(v or "")[:500]
            if k in ("tofu_dir", "inventory", "playbooks", "roles") and (not v or v.startswith(("/", "\\")) or ".." in pathlib.PurePosixPath(v).parts):
                raise Refused("Invalid {what}: {value}", what=k, value=v)
            out[k] = v
        g = out["git"] = {**DEFAULTS["git"], **out["git"]}
        if g["url"].startswith("-") or not re.fullmatch(r"[A-Za-z0-9._/-]+", g["branch"]) or g["branch"].startswith("-"):
            raise Refused("Invalid {what}: {value}", what="git", value=(g["url"] or g["branch"])[:80])
        if not str(g["depth"]).isdigit() or not 1 <= int(g["depth"]) <= 100000:
            raise Refused("Invalid {what}: {value}", what="git depth", value=str(g["depth"])[:20])
        g["depth"] = int(g["depth"])
        if g.get("mode") not in ("push", "branch", "agit"):
            raise Refused("Invalid {what}: {value}", what="git mode", value=str(g.get("mode"))[:20])
        for k in ("name", "email"):
            if not g[k] or re.search(r"[<>\n]", g[k]):
                raise Refused("Invalid {what}: {value}", what=f"git {k}", value=g[k][:40])
        with self.lock:
            if g["url"] != cur["git"]["url"]:
                shutil.rmtree(self.data / "repo", ignore_errors=True)
            self.save_settings(out)
            self.synced = 0
            self.sync(self.settings(), force=True)
        return {"ok": True, "sync_error": self.sync_error}

    def test_git(self):
        s = self.settings()
        if not s["git"]["url"]:
            raise Refused("No Git remote set")
        self.git(self.data, "ls-remote", "--heads", "--", s["git"]["url"], s["git"]["branch"], timeout=30)
        return {"ok": True}


CSP = ("default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; connect-src 'self'; "
       "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")


def serve(cfg):
    app = App(cfg)

    class H(http.server.BaseHTTPRequestHandler):
        server_version, sys_version = "cairn-iac", ""

        def send(self, code, body, ctype="application/json"):
            b = body if isinstance(body, bytes) else body.encode("utf-8") if isinstance(body, str) else json.dumps(body, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            for k, v in (("Content-Type", ctype if isinstance(body, bytes) else f"{ctype}; charset=utf-8"), ("Content-Length", str(len(b))), ("Cache-Control", "no-store"),
                         ("Content-Security-Policy", CSP), ("X-Content-Type-Options", "nosniff"), ("Referrer-Policy", "no-referrer")):
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(b)

        def do_GET(self):
            if self.path == "/healthz":
                return self.send(200, "ok\n", "text/plain")
            if self.path.split("?")[0] == "/favicon.ico":
                return self.send(200, favicon(), "image/png")
            user = app.user(self)
            if not user:
                return self.send(403, "access denied\n", "text/plain")
            if self.path.startswith("/api/history?"):
                try:
                    return self.send(200, app.history(urllib.parse.parse_qs(self.path.split("?", 1)[1]).get("machine", [""])[0]))
                except Refused as e:
                    return self.send(409, {"error": e.msg, "vars": e.v})
                except subprocess.TimeoutExpired:
                    return self.send(504, {"error": "Git did not answer in time"})
            if self.path.split("?")[0] != "/":
                return self.send(404, "not found\n", "text/plain")
            self.send(200, app.page(user), "text/html")

        def do_POST(self):
            user = app.user(self)
            if not user:
                return self.send(403, {"error": "Access denied"})
            # CSRF: JSON only (a cross-site form cannot send it without a preflight, never answered), same origin.
            origin = self.headers.get("Origin", "")
            if not self.headers.get("Content-Type", "").startswith("application/json") or \
                    (origin and origin.split("://")[-1] != self.headers.get("Host", "")):
                return self.send(400, {"error": "Invalid request"})
            n = int(self.headers.get("Content-Length") or 0)
            if n > 65536:
                return self.send(413, {"error": "Invalid request"})
            try:
                body = json.loads(self.rfile.read(n) or b"{}")
                if not isinstance(body, dict):
                    raise ValueError
            except ValueError:
                return self.send(400, {"error": "Invalid request"})
            try:
                if self.path == "/api/preview":
                    out = app.edit(self, user, body, False)
                elif self.path == "/api/commit":
                    out = app.edit(self, user, body, True)
                elif self.path == "/api/settings":
                    out = app.put_settings(body)
                elif self.path == "/api/git-test":
                    out = app.test_git()
                else:
                    return self.send(404, {"error": "Not found"})
                print(f"cairn-iac: {user} {self.path} {body.get('op', '')}", file=sys.stderr)
                self.send(200, out)
            except Refused as e:
                self.send(409, {"error": e.msg, "vars": e.v})
            except subprocess.TimeoutExpired:
                self.send(504, {"error": "Git did not answer in time"})

        def log_message(self, fmt, *args):
            pass

    host, _, port = cfg["listen"].rpartition(":")
    srv = http.server.ThreadingHTTPServer((host.strip("[]") or "0.0.0.0", int(port)), H)
    print(f"cairn-iac: serving on {cfg['listen']}, data in {app.data}", file=sys.stderr)
    srv.serve_forever()


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("-c", "--config", type=pathlib.Path, help="JSON config (default: none, current directory is the repo)")
    ap.add_argument("-o", "--output", type=pathlib.Path, default=pathlib.Path("iac.html"))
    ap.add_argument("--serve", action="store_true", help="serve the page with editing (see README, Server)")
    ap.add_argument("--check", action="store_true", help="print the drift findings, exit 1 if one is a warning (CI)")
    ap.add_argument("--json", action="store_true", help="with --check: the findings as JSON; alone: the whole model as JSON")
    a = ap.parse_args()
    cfg_path = a.config.resolve() if a.config else None
    if a.check:
        sys.exit(check(cfg_path, a.json))
    if a.json:
        sys.exit(dump(cfg_path))
    serve(load_config(cfg_path)) if a.serve else build(cfg_path, a.output)
