#!/usr/bin/env python3
"""cairn-iac: one HTML page showing what an OpenTofu + Ansible repo builds.

For each machine: what Tofu creates (CPU, memory, disk, IP, the HCL block),
its guest firewall, and the Ansible roles it receives (with their task names).

    python3 cairn-iac.py -c cairn-iac.json -o iac.html      # static page
    python3 cairn-iac.py -c server.json --serve             # page + edits, Git commit and push

Needs Python 3.8+ and PyYAML (Debian: python3-yaml); the server also needs git
(and ssh for an ssh:// remote). Never runs tofu or ansible.
"""
import argparse, difflib, http.server, ipaddress, json, os, pathlib, re, shutil, subprocess, sys, threading, time

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
    # Server only: where new guest firewall rules go in a firewall module.
    "firewall_lists": {"in": "inbound_rules", "out": "outbound_rules"},
    # mode: push (to the branch), branch (a new branch per edit, to open a pull request from),
    # agit (Forgejo/Gitea AGit: refs/for/<branch> opens the pull request itself).
    "git": {"url": "", "branch": "main", "push": True, "mode": "push", "name": "Cairn IaC", "email": "cairn-iac@localhost", "commit_prefix": ""},
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
    return (kind == "resource" and a == FW_RESOURCE) or (kind == "module" and re.search(r'^  \w+_rules\s*=\s*\[', body, re.M))


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


def read_tofu(tofu_dir, repo):
    machines, firewalls = [], {}
    for tf in sorted(tofu_dir.glob("*.tf")):
        rel = tf.relative_to(repo).as_posix()
        for (kind, a, b), line, body in blocks(tf.read_text(encoding="utf-8")):
            cid = val(body, "container_id") or val(body, "vm_id")
            if is_firewall(kind, a, body) and cid:
                label = b if kind == "resource" else a
                fw = firewalls.setdefault(cid, {"name": re.sub(r"^(firewall|fw)_", "", label), "node": val(body, "node_name"),
                                                "file": rel, "line": line, "rules": []})
                fw["rules"] += [{"dir": d, "at": [rel, line, i], **{k: kv(body[s:e], k) for k in ("proto", "dport", "source", "dest", "comment")}}
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


def collect(cfg, repo):
    machines, firewalls = read_tofu(repo / cfg["tofu_dir"], repo)
    groups, direct, ips, playbooks, roles = read_ansible(cfg, repo)
    inv_parent = (repo / cfg["inventory"]).parent.parent
    try:
        pb_prefix = (repo / cfg["playbooks"]).relative_to(inv_parent).as_posix() + "/"
    except ValueError:
        pb_prefix = cfg["playbooks"].rstrip("/") + "/"
    return {
        "title": cfg["title"], "subtitle": cfg["subtitle"], "lang": cfg["lang"], "rev": git_rev(repo),
        "workflow": cfg["workflow"], "note": cfg["note"], "playbook_prefix": pb_prefix,
        "generic_playbooks": cfg["generic_playbooks"], "links": cfg["links"],
        "paths": {k: pathlib.PurePosixPath(cfg[k]).as_posix() for k in ("inventory", "playbooks", "roles")},
        "nodes": groups.get(cfg["node_group"], []), "bare": groups.get(cfg["bare_metal_group"], []),
        "tofu": machines, "firewalls": firewalls, "groups": groups, "direct": direct, "ips": ips,
        "playbooks": playbooks, "roles": roles, "server": None,
    }


def collect_empty(cfg):
    return {"title": cfg["title"], "subtitle": cfg["subtitle"], "lang": cfg["lang"], "rev": "", "workflow": {}, "note": None,
            "playbook_prefix": "", "generic_playbooks": [], "links": {}, "paths": {"inventory": "", "playbooks": "", "roles": ""},
            "nodes": [], "bare": [], "tofu": [], "firewalls": {}, "groups": {}, "direct": {}, "ips": {}, "playbooks": {}, "roles": {}, "server": None}


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
          f"{len(data['ips'])} inventory hosts, {len(data['playbooks'])} playbooks, {len(data['roles'])} roles)")


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


def role_add(text, host, role):
    name_ok(host, "host"), name_ok(role, "role")
    # ponytail: a new play per (host, role); merging into an existing play's roles list is left to the reviewer.
    out = text + ("" if not text or text.endswith("\n") else "\n") + f"\n- name: {role} ({host})\n  hosts: {host}\n  roles:\n    - {role}\n"
    plays = yaml.safe_load(out)
    if not isinstance(plays, list) or plays[-1].get("roles") != [role]:
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
        self.synced, self.sync_error, self.cache = 0.0, "", (None, None)
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
        r = subprocess.run(["git", "-C", str(repo), *args], env=env, capture_output=True, text=True, timeout=timeout)
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
                self.git(self.data, "clone", "-q", "--depth", "50", "--branch", g["branch"], "--", g["url"], str(repo), timeout=300)
            else:
                self.git(repo, "remote", "set-url", "origin", g["url"])
                self.git(repo, "fetch", "-q", "--depth", "50", "origin", g["branch"], timeout=120)
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

    def page(self, user):
        with self.lock:
            s = self.settings()
            self.sync(s)
            repo = self.repo(s)
            rev = self.head(repo)
            stamp = (rev, self.settings_file.stat().st_mtime)
            if self.cache[0] != stamp or not rev:
                try:
                    self.cache = (stamp, collect(s, repo))
                except (OSError, yaml.YAMLError) as e:  # no clone yet, wrong paths: the Settings page stays reachable
                    self.cache = (None, {**collect_empty(s), "error": str(e)})
            data = dict(self.cache[1])
        pub = pathlib.Path(f"{self.key}.pub")
        data["server"] = {
            "user": user, "rev": rev, "edit": not self.cfg["read_only"], "settings": {k: s[k] for k in SETTINGS},
            "key": pub.read_text().strip() if pub.exists() else "", "sync_error": self.sync_error,
            "synced": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.synced)) if self.synced else "",
        }
        return render(data)

    def author(self, h, user):
        name = h.headers.get(self.cfg["name_header"], "").strip() if self.proxies else ""
        mail = h.headers.get(self.cfg["email_header"], "").strip() if self.proxies else ""
        name = name if name and not re.search(r"[<>\n]", name) else user
        mail = mail if re.fullmatch(r"[^<>\s@]+@[^<>\s@]+", mail) else f"{user}@cairn-iac"
        return f"{name} <{mail}>"

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
                         "commit", "-q", "--author", self.author(h, user), "-m", text)
                sha = self.git(repo, "rev-parse", "--short", "HEAD")
                mode, ref, link = g.get("mode") or "push", g["branch"], ""
                if g["url"] and g["push"]:
                    topic = "cairn-iac/" + re.sub(r"[^A-Za-z0-9_.-]", "-", user)[:40] + time.strftime("-%Y%m%d-%H%M%S")
                    if mode == "agit":
                        out = self.git(repo, "push", "origin", f"HEAD:refs/for/{g['branch']}", "-o", f"topic={topic}",
                                       "-o", "title=" + text.splitlines()[0][:200], timeout=120, output=True)
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
            b = body.encode("utf-8") if isinstance(body, str) else json.dumps(body, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            for k, v in (("Content-Type", f"{ctype}; charset=utf-8"), ("Content-Length", str(len(b))), ("Cache-Control", "no-store"),
                         ("Content-Security-Policy", CSP), ("X-Content-Type-Options", "nosniff"), ("Referrer-Policy", "no-referrer")):
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(b)

        def do_GET(self):
            if self.path == "/healthz":
                return self.send(200, "ok\n", "text/plain")
            user = app.user(self)
            if not user:
                return self.send(403, "access denied\n", "text/plain")
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
    a = ap.parse_args()
    cfg_path = a.config.resolve() if a.config else None
    serve(load_config(cfg_path)) if a.serve else build(cfg_path, a.output)
