"""Smoke test on example/: python3 test_cairn_iac.py"""
import json, os, pathlib, shutil, subprocess, sys, tempfile, importlib.util

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("cairn_iac", HERE / "cairn-iac.py")
ci = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ci)

# ---- the static page ----
with tempfile.TemporaryDirectory() as tmp:
    out = pathlib.Path(tmp) / "iac.html"
    ci.build(HERE / "example/cairn-iac.json", out)
    page = out.read_text(encoding="utf-8")
    data = json.loads(page.split("const D = ")[1].split(";\n")[0])

web, db, backup = data["tofu"]
assert (web["name"], web["kind"], web["node"], web["id"], web["cores"], web["memory"], web["disk"], web["ip"]) == \
       ("web", "LXC", "pve1", 201, "2", "2048", "16", "10.0.0.21"), web
assert (db["kind"], db["memory"], db["disk"], db["ip"]) == ("VM", "8192", "64", "10.0.0.22"), db
rules = data["firewalls"]["201"]["rules"]
assert [(r["dir"], r["dport"], r["at"][2]) for r in rules] == [("in", "443", 0), ("out", "5432", 1)], rules
assert data["playbooks"]["site"][0]["hosts"] == ["db", "pve1", "pve2", "web"]
assert data["roles"]["web"]["tasks"] == ["Install nginx", "Write the site configuration"]
assert data["roles"]["web"]["templates"] == ["site.conf.j2"]
assert data["nodes"] == ["pve1", "pve2"] and data["playbook_prefix"] == "playbooks/"
assert data["direct"]["guests"] == ["db", "web"]
assert "<title>Example lab</title>" in page and "/*DATA*/" not in page
assert "#nav button[hidden] { display: none; }" in page  # server-only views stay out of the static page

# ---- drift: each kind once in the example (more.tf, the inventory's db and printer) ----
found = {(f["kind"], f["severity"], f["machine"], f["file"], f["line"]) for f in data["findings"]}
assert found == {
    ("firewall_off", "warn", "backup", "tofu/more.tf", 32), ("firewall_orphan", "warn", "old", "tofu/more.tf", 78),
    ("ip_mismatch", "warn", "db", "tofu/main.tf", 32), ("not_in_inventory", "warn", "backup", "tofu/more.tf", 4),
    ("required_roles", "warn", "printer", "ansible/inventory/hosts.yml", 18),
    ("firewall_no_options", "info", "db", "tofu/more.tf", 54), ("no_playbook", "info", "printer", "ansible/inventory/hosts.yml", 18),
    ("not_in_tofu", "info", "printer", "ansible/inventory/hosts.yml", 18), ("half_open", "info", "db", "tofu/more.tf", 67),
    ("over_allocated", "warn", "pve2", "", 0)}, found
assert next(f for f in data["findings"] if f["kind"] == "ip_mismatch")["vars"] == {"name": "db", "tofu": "10.0.0.22", "inventory": "10.0.0.32"}
fw = data["firewalls"]
assert (fw["201"]["enabled"], fw["201"]["input_policy"], fw["203"]["enabled"], fw["202"]["options"]) == (True, "DROP", False, None)
mod = ci.fw_state('module "fw_x" {\n  container_id = 9\n  enabled      = false # later\n  rule { enabled = true }\n}')
assert mod == {"enabled": False, "input_policy": None, "output_policy": None}, mod
# a firewall module with base rules only (no *_rules list) is a firewall, not a machine
assert ci.is_firewall("module", "firewall_x", 'module "firewall_x" {\n  source = "./modules/guest-firewall"\n  vm_id  = 9\n}')
cli = lambda *a: subprocess.run([sys.executable, str(HERE / "cairn-iac.py"), "-c", str(HERE / "example/cairn-iac.json"), "--check", *a],
                                capture_output=True, text=True)
r = cli("--json")
assert r.returncode == 1 and len(json.loads(r.stdout)) == 10, r
assert "db: Tofu gives 10.0.0.22, the inventory 10.0.0.32" in cli().stdout
assert "node_capacity  pve2 gives its guests 5 vCPU, more than the 4 declared" in cli().stdout

# ---- node capacity: sums of what Tofu gives each node's guests, against the declared totals ----
cap = data["capacity"]
assert {n: (c["guests"], c["cores"], c["memory"], c["disk"], c["total"]) for n, c in cap.items()} == {
    "pve1": (1, 2, 2048, 16, {"cores": 8, "memory": 16384, "disk": 200}),
    "pve2": (2, 5, 9216, 164, {"cores": 4, "memory": 10240, "disk": 500})}, cap  # memory declared in GiB
# a value Tofu does not give literally (a variable, or nothing) is unknown, not counted; a node declared alone shows up
# declared memory is in GiB, kept in Tofu's MiB like the sums
c = ci.capacity([{"name": "a", "node": "N1", "cores": "var.cores", "memory": "2048 # note", "disk": None}], {"n2": {"cores": 4, "memory": 3}})
assert (c["n1"]["cores"], c["n1"]["unknown"], c["n1"]["memory"], c["n2"]["total"]) ==        (0, {"cores": ["a"], "memory": [], "disk": ["a"]}, 2048, {"cores": 4, "memory": 3072}), c
f = ci.drift({**ci.DEFAULTS}, [], {}, {}, {}, {}, "", cap={"n": {**c["n1"], "name": "N", "total": {"memory": 1024}}})
assert [x["msg"].format(**x["vars"]) for x in f] == ["N gives its guests 2 GiB of memory, more than the 1 declared"], f
f = ci.drift({**ci.DEFAULTS}, [], {}, {}, {}, {}, "", cap={"n": {**c["n1"], "name": "N", "disk": 1100, "total": {"disk": 1024}}})
assert [x["msg"].format(**x["vars"]) for x in f] == ["N gives its guests 1.07 TB of disk, more than the 1 declared"], f

# ---- machines merged from Tofu, the firewalls and the inventory ----
mm = {m["key"]: m for m in data["machines"]}
assert mm["web"] == {"key": "web", "name": "web", "host": "web", "node": "pve1", "id": 201, "ip": "10.0.0.21",
                     "tofu": {"kind": "LXC", "address": "proxmox_virtual_environment_container.web", "cores": "2", "memory": "2048",
                              "disk": "16", "file": "tofu/main.tf", "line": 2},
                     "firewall": "201", "phys": False, "groups": ["guests"], "roles": ["base", "web"], "playbooks": ["site"]}, mm["web"]
assert (mm["old"]["id"], mm["old"]["tofu"], mm["old"]["host"]) == (299, None, None) and mm["pve1"]["phys"]

# ---- --json alone: the model, the same as the page's "Download JSON" ----
r = subprocess.run([sys.executable, str(HERE / "cairn-iac.py"), "-c", str(HERE / "example/cairn-iac.json"), "--json"], capture_output=True, text=True)
model = json.loads(r.stdout)
assert r.returncode == 0 and list(model) == list(ci.EXPORT) and model == {k: data[k] for k in ci.EXPORT}, r.stderr
assert all("code" not in m and "code" not in (m["tofu"] or {}) for m in model["machines"])
assert 'const EXPORT = ["' + '", "'.join(ci.EXPORT) + '"]' in page  # the page downloads the same keys

# ---- flows: each rule resolved to machines; half-open ones flagged ----
fl = {(f["owner"], f["dir"], f["src"]["k"], f["dst"]["k"], f["dport"]): f for f in data["flows"]}
assert fl["web", "out", "web", "db", "5432"]["half"] is False and fl["db", "in", "web", "db", "5432"]["line"] == 58
assert fl["db", "out", "db", "web", "8443"]["half"] is True
lan = fl["backup", "in", None, "backup", "22"]["src"]
assert lan == {"k": None, "a": "10.0.0.0/24", "n": ["backup", "db", "printer", "pve1", "pve2", "web"], "wide": True}, lan
assert fl["web", "in", None, "web", "443"]["src"] == {"k": None, "a": "", "n": [], "wide": True}
assert next(f for f in data["findings"] if f["kind"] == "half_open")["vars"] == {"src": "db", "dst": "web", "what": "tcp/8443"}
assert (ci.port_ranges("1514,1515"), ci.port_ranges("137:138"), ci.port_ranges("")) == ([(1514, 1514), (1515, 1515)], [(137, 138)], None)
assert ci.nets("0.0.0.0/0") is None and [str(n) for n in ci.nets("10.0.0.2,10.0.0.80")] == ["10.0.0.2/32", "10.0.0.80/32"]
assert ci.same_traffic({"proto": "tcp", "dport": "1514,1515"}, {"proto": "tcp", "dport": "1515"})
assert not ci.same_traffic({"proto": "udp", "dport": "53"}, {"proto": "tcp", "dport": "53"})

# a firewall module: its own literal rules apply to each machine using it; the reverse half-open (in without out)
with tempfile.TemporaryDirectory() as tmp:
    repo = pathlib.Path(tmp)
    (repo / "tofu/modules/fw").mkdir(parents=True)
    (repo / "tofu/modules/fw/main.tf").write_text("""resource "proxmox_virtual_environment_firewall_rules" "this" {
  vm_id = var.vm_id

  rule {
    type   = "out"
    proto  = "tcp"
    dport  = "4317"
    dest   = "10.0.0.9/32"
  }
  rule {
    type   = "in"
    source = var.admin
  }
  rule {
    type   = "in"
    source = local.other
  }
}
variable "admin" {
  description = "admin network"
  default     = "10.0.0.0/24"
}
""")
    (repo / "tofu/main.tf").write_text("""module "fw_a" {
  source = "./modules/fw"
  vm_id  = 1
  inbound_rules = [
    { comment = "from b", proto = "tcp", dport = "80", source = "10.0.0.2/32" },
  ]
}
module "fw_b" {
  source = "./modules/fw"
  vm_id  = 2
  admin  = "10.0.0.9/32"
  inbound_rules = [
  ]
}
""")
    ms = [{"name": n, "id": None, "ip": ip} for n, ip in (("a", "10.0.0.1"), ("b", "10.0.0.2"), ("obs", "10.0.0.9"))]
    _, fws = ci.read_tofu(repo / "tofu", repo)
    # var. from the call, else the variable's default; local. stays unknown, the rule is skipped
    assert [(r["dir"], r["dport"], r["source"], r["line"]) for r in fws["1"]["common"]] == [("out", "4317", None, 4), ("in", None, "10.0.0.0/24", 10)]
    assert [r["source"] for r in fws["2"]["common"]] == [None, "10.0.0.9/32"] and fws["1"]["common"][0]["at"][0] == "tofu/modules/fw/main.tf"
    fl2 = ci.flows(ms, fws, {})
    assert [(f["src"]["k"], f["dst"]["k"], f["common"]) for f in fl2] == [
        ("b", "a", False), ("a", "obs", True), (None, "a", True), ("b", "obs", True), ("obs", "b", True)], fl2
    half = list(ci.half_open(fl2, fws, ms, {}))
    assert [(f["src"]["k"], f["dst"]["k"], f["dport"]) for f in half] == [("b", "a", "80")], half

# ---- a Tofu state or saved plan is never read (they can hold secrets) ----
with tempfile.TemporaryDirectory() as tmp:
    repo = pathlib.Path(tmp) / "repo"
    shutil.copytree(HERE / "example", repo)
    marker = "LEAK-MARKER-from-the-state-file"
    for name in ("terraform.tfstate", "terraform.tfstate.backup", "web.plan"):
        (repo / "tofu" / name).write_text(f'resource "proxmox_virtual_environment_vm" "leak" {{\n  name = "{marker}"\n  vm_id = 9\n}}\n')
    out = pathlib.Path(tmp) / "iac.html"
    ci.build(repo / "cairn-iac.json", out)
    assert marker not in out.read_text(encoding="utf-8")
    r = subprocess.run([sys.executable, str(HERE / "cairn-iac.py"), "-c", str(repo / "cairn-iac.json"), "--json"], capture_output=True, text=True)
    assert r.returncode == 0 and marker not in r.stdout

# ---- edits, on a copy of the example made a Git repo ----
def refused(f, *a):
    try:
        f(*a)
    except ci.Refused as e:
        return e.msg.format(**e.v)
    raise AssertionError(f"not refused: {f.__name__}{a}")

with tempfile.TemporaryDirectory() as tmp:
    repo = pathlib.Path(tmp) / "repo"
    shutil.copytree(HERE / "example", repo)
    git = lambda *a: subprocess.run(["git", "-C", str(repo), *a], check=True, capture_output=True, text=True).stdout
    git("init", "-q", "-b", "main"); git("add", "."); git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "init")
    cfg = ci.load_config(repo / "cairn-iac.json")

    def run(op):
        r = ci.apply(op, cfg, repo)
        for rel, old, new in r["files"]:
            (repo / rel).write_text(new, encoding="utf-8", newline="")
        return r["message"]

    # resources: VM nested blocks (cpu.cores, memory.dedicated, disk.size)
    assert run({"op": "resources", "file": "tofu/main.tf", "line": 32, "name": "db", "cores": 6, "memory": 16384, "disk": 80}) == \
           "db: cores 4 -> 6, memory 8192 -> 16384, disk 64 -> 80"
    d = {m["name"]: m for m in ci.read_tofu(repo / "tofu", repo)[0]}["db"]
    assert (d["cores"], d["memory"], d["disk"]) == ("6", "16384", "80"), d
    assert "shrink" in refused(ci.apply, {"op": "resources", "file": "tofu/main.tf", "line": 32, "disk": 10}, cfg, repo)
    assert "reload" in refused(ci.apply, {"op": "resources", "file": "tofu/main.tf", "line": 33, "cores": 2}, cfg, repo)
    assert "Unknown file" in refused(ci.apply, {"op": "resources", "file": "../x.tf", "line": 1}, cfg, repo)

    # firewall: add then remove, provider resource
    rule = {"dir": "in", "proto": "tcp", "dport": "22", "addr": "10.0.0.0/24", "comment": "SSH from the LAN"}
    run({"op": "fw_add", "file": "tofu/main.tf", "line": 61, "name": "web", "rule": rule})
    fw = ci.read_tofu(repo / "tofu", repo)[1]["201"]["rules"]
    assert (fw[-1]["dir"], fw[-1]["dport"], fw[-1]["source"], fw[-1]["comment"]) == ("in", "22", "10.0.0.0/24", "SSH from the LAN"), fw
    assert "comment" in refused(ci.check_rule, {**rule, "comment": 'a"b'})
    assert "port" in refused(ci.check_rule, {**rule, "dport": "70000"})
    run({"op": "fw_del", "file": "tofu/main.tf", "line": 61, "index": 0})
    assert [r["dport"] for r in ci.read_tofu(repo / "tofu", repo)[1]["201"]["rules"]] == ["5432", "22"]

    # firewall: a module with rule lists, one rule per line, and a list created when missing
    mod = 'module "fw_web" {\n  source       = "./fw"\n  container_id = 301\n\n  inbound_rules = [\n    { comment = "a", proto = "tcp", dport = "80" },\n  ]\n}'
    lists = {"in": "inbound_rules", "out": "extra_egress_rules"}
    b = ci.fw_add(mod, {"dir": "out", "proto": "udp", "dport": "53", "addr": "10.0.0.2", "comment": "DNS"}, lists)
    b = ci.fw_add(b, {"dir": "in", "proto": "icmp", "comment": "ping"}, lists)
    assert [(d, b[s:e]) for d, s, e in ci.fw_rules(b)] == [
        ("in", '{ comment = "a", proto = "tcp", dport = "80" }'), ("in", '{ comment = "ping", proto = "icmp" }'),
        ("out", '{ comment = "DNS", proto = "udp", dport = "53", dest = "10.0.0.2" }')], b
    assert ci.fw_rules(ci.fw_del(b, 0))[0][0] == "in" and len(ci.fw_rules(ci.fw_del(b, 0))) == 2

    # inventory: add to a group (new machine with its address), remove; vars are protected
    run({"op": "group_add", "group": "guests", "host": "cache", "ip": "10.0.0.23"})
    groups, direct, ips = ci.read_inventory((repo / cfg["inventory"]).read_text(encoding="utf-8"))
    assert "cache" in direct["guests"] and ips["cache"] == "10.0.0.23"
    assert "variables" in refused(ci.apply, {"op": "group_del", "group": "guests", "host": "cache"}, cfg, repo)
    run({"op": "group_add", "group": "proxmox_nodes", "host": "web"})
    run({"op": "group_del", "group": "proxmox_nodes", "host": "web"})
    assert ci.read_inventory((repo / cfg["inventory"]).read_text(encoding="utf-8"))[1]["proxmox_nodes"] == ["pve1", "pve2"]

    # a role for a host: a new play, then a second role goes into that play's roles list
    run({"op": "role_add", "playbook": "site", "role": "web", "host": "db"})
    groups, direct, ips, pbs, roles = ci.read_ansible(cfg, repo)
    assert pbs["site"][-1] == {"hosts": ["db"], "roles": ["web"]}
    run({"op": "role_add", "playbook": "site", "role": "base", "host": "db"})
    assert ci.read_ansible(cfg, repo)[3]["site"] == pbs["site"][:-1] + [{"hosts": ["db"], "roles": ["web", "base"]}]
    assert "Unknown role" in refused(ci.apply, {"op": "role_add", "playbook": "site", "role": "nope", "host": "db"}, cfg, repo)
    # into the middle play, list at the key's indent, an item with sub-keys, a comment after; other plays untouched
    pb = ("---\n- hosts: a\n  roles:\n    - x\n- name: B\n  hosts: b  # the b box\n  roles:\n  - x\n  - role: y\n    vars: {z: 1}\n"
          "\n  # tasks next\n  tasks:\n    - debug: {}\n- hosts: b\n  roles: [x]\n")
    out = ci.role_add(pb, "b", "w")
    assert out == pb.replace("    vars: {z: 1}\n", "    vars: {z: 1}\n  - w\n"), out
    # no play for exactly that host, or a flow-style list only: a new play
    assert ci.role_add("- hosts: b\n  roles: [x]\n", "b", "w").endswith("\n- name: w (b)\n  hosts: b\n  roles:\n    - w\n")
    assert ci.role_add("- hosts: b:c\n  roles:\n    - x\n", "b", "w").count("hosts: b\n") == 1

    # the server's commit path, without a remote: author from the proxy headers
    app = ci.App({**cfg, "data_dir": str(pathlib.Path(tmp) / "data"), "repo": str(repo), "base": repo})
    git("checkout", "-q", "--", ".")
    class Req:
        headers = {"Remote-Name": "Ada Lovelace", "Remote-Email": "ada@example.org"}
    app.proxies = ["x"]  # as if behind a proxy, for the author headers
    head = app.head(repo)
    op = {"op": "resources", "file": "tofu/main.tf", "line": 2, "name": "web", "cores": 3, "rev": head}
    assert "+    cores = 3" in app.edit(Req, "ada", op, False)["diff"]
    out = app.edit(Req, "ada", op, True)
    assert out["ok"] and not out["pushed"]
    assert git("log", "-1", "--format=%an <%ae>|%cn|%s").strip() == "Ada Lovelace <ada@example.org>|Cairn IaC|web: cores 2 -> 3"
    assert "moved" in refused(app.edit, Req, "ada", op, False)

    # remote modes: "branch" pushes a new branch and leaves the remote branch (and the clone) as they were
    bare = pathlib.Path(tmp) / "remote.git"
    subprocess.run(["git", "clone", "-q", "--bare", str(repo), str(bare)], check=True)
    data2 = pathlib.Path(tmp) / "data2"
    app2 = ci.App({**cfg, "data_dir": str(data2), "base": repo, "git": {**cfg["git"], "url": bare.as_posix(), "mode": "branch"}})
    app2.proxies = ["x"]
    page = app2.page("ada")
    rev = json.loads(page.split("const D = ")[1].split(";\n")[0])["server"]["rev"]
    out = app2.edit(Req, "ada", {**op, "cores": 5, "rev": rev}, True)
    assert out["mode"] == "branch" and out["ref"].startswith("cairn-iac/ada-"), out
    bgit = lambda *a: subprocess.run(["git", "-C", str(bare), *a], check=True, capture_output=True, text=True).stdout.strip()
    assert bgit("rev-parse", "main") == rev and bgit("log", "-1", "--format=%s", out["ref"]) == "web: cores 3 -> 5"
    assert app2.head(data2 / "repo") == rev
    sm = app2.summary()  # dashboards: /api/summary
    assert sm["rev"] == rev[:7] and sm["machines"] >= 1 and sm["warnings"] + sm["notes"] >= 0 and not sm["error"], sm
    assert "mode" in refused(app2.put_settings, {"git": {**cfg["git"], "mode": "nope"}})
    assert "node_capacity" in refused(app2.put_settings, {"node_capacity": {"pve1": {"cores": "8"}}})
    assert "node" in refused(app2.put_settings, {"node_capacity": {"pve 1": {"cores": 8}}})
    app2.put_settings({"node_capacity": {"pve1": {"cores": 8, "memory": 4096}, "pve2": {}}})
    assert app2.settings()["node_capacity"] == {"pve1": {"cores": 8, "memory": 4096}}
    assert "depth" in refused(app2.put_settings, {"git": {**cfg["git"], "depth": "0"}})

    # AGit: who proposed it and the commit body in the pull request description, on one line
    assert ci.agit_push("main", "t", "web: cores 2 -> 3\n\nWhy:\nmore load", "Ada Lovelace (ada)") == [
        "push", "origin", "HEAD:refs/for/main", "-o", "topic=t", "-o", "title=web: cores 2 -> 3",
        "-o", "description=Proposed by Ada Lovelace (ada) from Cairn IaC. Why: more load"]
    assert ci.agit_push("main", "t", "x", "ada")[-1] == "description=Proposed by ada from Cairn IaC."

# ---- a machine's history: its Tofu block, its firewall, the inventory lines naming it; shallow clone cut ----
with tempfile.TemporaryDirectory() as tmp:
    repo = pathlib.Path(tmp) / "repo"
    shutil.copytree(HERE / "example", repo)
    git = lambda *a: subprocess.run(["git", "-C", str(repo), *a], check=True, capture_output=True, text=True).stdout
    n = iter(range(10))  # one commit a minute, so the newest-first order does not depend on the clock
    commit = lambda m, who="t": subprocess.run(["git", "-C", str(repo), "-c", f"user.name={who}", "-c", "user.email=t@t", "commit", "-qam", m],
                                               check=True, capture_output=True, env={**os.environ, "GIT_COMMITTER_DATE": f"2026-01-01T00:0{next(n)}:00Z"})
    git("init", "-q", "-b", "main"); git("add", "."); commit("init")
    edit = lambda f, a, b: (repo / f).write_text((repo / f).read_text(encoding="utf-8").replace(a, b, 1), encoding="utf-8", newline="\n")
    edit("tofu/main.tf", "cores = 2", "cores = 3"); commit("web: cores 2 -> 3", "ada")
    edit("tofu/main.tf", "cores = 4", "cores = 6"); commit("db: cores")             # db only
    edit("tofu/main.tf", '"5432"', '"5433"'); commit("web: firewall port")         # web's firewall block
    edit("ansible/inventory/hosts.yml", "10.0.0.21", "10.0.0.31"); commit("inventory: web address")  # web's lines
    pb = repo / "ansible/playbooks/site.yml"
    pb.write_text(ci.role_add(pb.read_text(encoding="utf-8"), "web", "base"), encoding="utf-8", newline=""); commit("site: base on web")
    edit("ansible/inventory/hosts.yml", "printer:\n", "printer:\n          ansible_port: 22\n"); commit("printer port")
    cfg = ci.load_config(repo / "cairn-iac.json")
    app = ci.App({**cfg, "data_dir": str(pathlib.Path(tmp) / "data"), "base": repo})
    h = app.history("web")
    assert [(c["subject"], c["what"]) for c in h["commits"]] == [
        ("site: base on web", ["playbook"]), ("inventory: web address", ["inventory"]), ("web: firewall port", ["firewall"]), ("web: cores 2 -> 3", ["tofu"]),
        ("init", ["tofu", "firewall", "inventory", "playbook"])], h
    assert h["commits"][3]["author"] == "ada" and not h["truncated"] and not h["shallow"] and "cut" not in h["commits"][0]
    assert app.history("web") is h  # cached at this commit
    assert "Unknown machine" in refused(app.history, "nope")
    # a clone 3 commits deep: the oldest one reached is the boundary, what came before is not there
    bare = pathlib.Path(tmp) / "remote.git"
    subprocess.run(["git", "clone", "-q", "--bare", str(repo), str(bare)], check=True)
    app2 = ci.App({**cfg, "data_dir": str(pathlib.Path(tmp) / "data2"), "base": repo,
                   "git": {**cfg["git"], "url": bare.as_uri(), "depth": 3}})
    h = app2.history("web")
    assert [c["subject"] for c in h["commits"]] == ["site: base on web"] and h["truncated"] and h["since"] == "2026-01-01", h
    h = app2.history("db")  # the boundary commit carries every line of the files: not listed, the history is cut there
    assert h["truncated"] and h["shallow"] and h["commits"] == [] and h["depth"] == 3, h

# ---- a new machine from a model: Tofu block, guest firewall, inventory groups, a role; one commit ----
with tempfile.TemporaryDirectory() as tmp:
    repo = pathlib.Path(tmp) / "repo"
    shutil.copytree(HERE / "example", repo)
    git = lambda *a: subprocess.run(["git", "-C", str(repo), *a], check=True, capture_output=True, text=True).stdout
    git("init", "-q", "-b", "main"); git("add", "."); git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "init")
    cfg = ci.load_config(repo / "cairn-iac.json")
    web = {"op": "new_machine", "model": "proxmox_virtual_environment_container.web", "name": "cache", "host": "cache",
           "description": "Cache server", "vm_id": 204, "node": "PVE2", "ip": "10.0.0.24", "cores": 1, "memory": 1024, "disk": 8,
           "rules": True, "groups": ["guests"], "playbook": "site", "role": "web"}
    # provider resources: the container, its firewall rules and options copied; the inventory and a playbook, all in one edit
    r = ci.apply(web, cfg, repo)
    assert [f[0] for f in r["files"]] == ["tofu/main.tf", "ansible/inventory/hosts.yml", "ansible/playbooks/site.yml"], r["files"]
    assert r["message"] == "cache: new LXC 204 on pve2, 10.0.0.24 (model web)", r["message"]
    assert r["targets"] == ["proxmox_virtual_environment_container.cache", "proxmox_virtual_environment_firewall_rules.cache",
                            "proxmox_virtual_environment_firewall_options.cache"], r["targets"]
    for rel, old, new in r["files"]:
        assert new.startswith(old.rstrip()) or not rel.endswith(".tf"), rel  # Tofu: appended, the rest untouched
        (repo / rel).write_text(new, encoding="utf-8", newline="")
    tf = (repo / "tofu/main.tf").read_text(encoding="utf-8")
    assert '# cache: Cache server\nresource "proxmox_virtual_environment_container" "cache" {\n  node_name = "pve2"\n  vm_id     = 204\n  tags      = ["cache"]\n' in tf, tf
    assert 'address = "10.0.0.24/24"' in tf and 'gateway = "10.0.0.1"' in tf.partition('# cache:')[2] and "# Web server" not in tf.partition('# cache:')[2]
    ms, fws = ci.read_tofu(repo / "tofu", repo)
    c = next(m for m in ms if m["name"] == "cache")
    assert (c["id"], c["node"], c["ip"], c["cores"], c["memory"], c["disk"]) == (204, "pve2", "10.0.0.24", "1", "1024", "8"), c
    assert [(x["dir"], x["dport"], x["dest"]) for x in fws["204"]["rules"]] == [("in", "443", None), ("out", "5432", "10.0.0.22/32")]
    assert (fws["204"]["enabled"], fws["204"]["input_policy"], fws["204"]["name"]) == (True, "DROP", "cache")
    groups, direct, ips, pbs, roles = ci.read_ansible(cfg, repo)
    assert ips["cache"] == "10.0.0.24" and "cache" in direct["guests"] and pbs["site"][-1] == {"hosts": ["cache"], "roles": ["web"]}
    m = {x["key"]: x for x in ci.collect(cfg, repo)["machines"]}["cache"]
    assert (m["firewall"], m["host"], m["roles"]) == ("204", "cache", ["base", "web"]), m
    # no rule copied: the firewall blocks stay (on, DROP), empty
    r = ci.apply({**web, "name": "cache2", "host": "cache2", "vm_id": 205, "ip": "10.0.0.25", "rules": False, "playbook": "", "role": ""}, cfg, repo)
    tf2 = r["files"][0][2].split('"cache2"')[1]
    assert "rule {" not in tf2 and "HTTPS" not in tf2 and len(r["files"]) == 2, tf2
    for rel, old, new in r["files"]:
        (repo / rel).write_text(new, encoding="utf-8", newline="")
    fws = ci.read_tofu(repo / "tofu", repo)[1]
    assert fws["205"]["rules"] == [] and fws["205"]["enabled"] is True
    # a VM model, its firewall rules without options; the disk may be smaller than the model's
    r = ci.apply({**web, "model": "proxmox_virtual_environment_vm.db", "name": "db2", "host": "db2", "vm_id": 206, "ip": "10.0.0.26", "disk": 20}, cfg, repo)
    assert r["targets"] == ["proxmox_virtual_environment_vm.db2", "proxmox_virtual_environment_firewall_rules.db2"], r["targets"]

    # every refusal
    no = lambda **kw: refused(ci.apply, {**web, "name": "x9", "host": "x9", "vm_id": 290, "ip": "10.0.0.90", **kw}, cfg, repo)
    assert "Unknown machine" in no(model="module.nope")
    assert "already exists" in no(name="WEB", host="web") and "already exists" in no(name="printer", host="printer")
    assert "already exists" in no(name="old", host="old")  # a firewall's name
    assert "inventory name" in no(host="x8")
    assert "Invalid name" in no(name="9x", host="9x") and "Invalid name" in no(name="a b")
    assert "description" in no(description="") and "description" in no(description='a "b"')
    assert "already used in Tofu" in no(vm_id=203) and "already used in Tofu" in no(vm_id=299)  # 299: a firewall's id
    assert "between" in no(vm_id=50) and "Invalid vm_id" in no(vm_id="x")
    assert "Unknown node" in no(node="pve9")
    assert "model's network" in no(ip="10.0.1.5") and "model's network" in no(ip="10.0.0.1") and "model's network" in no(ip="10.0.0.255")
    assert "already used in the repository (ansible/inventory/hosts.yml:" in no(ip="10.0.0.40")
    assert "Invalid address" in no(ip="10.0.0.300")
    assert "at least one" in no(groups=[]) and "not found" in no(groups=["proxmox_nodes"]) and "not found" in no(groups=["nope"])
    assert "Unknown role" in no(role="nope")
    assert "between" in no(cores=0)

    # the server: one commit with every file, the diff of all of them, the commands to run
    app = ci.App({**cfg, "data_dir": str(pathlib.Path(tmp) / "data"), "repo": str(repo), "base": repo})
    git("checkout", "-q", "--", ".")
    class Req:
        headers = {}
    op = {**web, "rev": app.head(repo)}
    p = app.edit(Req, "ada", op, False)
    assert p["files"] == ["tofu/main.tf", "ansible/inventory/hosts.yml", "ansible/playbooks/site.yml"] and p["diff"].count("+++ b/") == 3, p
    assert p["targets"][0] == "proxmox_virtual_environment_container.cache"
    out = app.edit(Req, "ada", op, True)
    assert out["ok"] and out["targets"] == p["targets"]
    assert git("show", "--name-only", "--format=%an|%s", "HEAD").split() == [
        "ada|cache:", "new", "LXC", "204", "on", "pve2,", "10.0.0.24", "(model", "web)",
        "ansible/inventory/hosts.yml", "ansible/playbooks/site.yml", "tofu/main.tf"]
    assert "already exists" in refused(app.edit, Req, "ada", {**op, "rev": app.head(repo)}, False)

# module models: the machine and its firewall module (rules lists, depends_on, its own address in a rule)
with tempfile.TemporaryDirectory() as tmp:
    repo = pathlib.Path(tmp)
    (repo / "tofu").mkdir()
    (repo / "inv").mkdir()
    (repo / "pb").mkdir()
    (repo / "roles").mkdir()
    (repo / "tofu/main.tf").write_text('''# The proxy, in front of everything.
module "proxy" {
  source    = "./modules/lxc"
  node_name = "N1"

  vm_id       = 110
  hostname    = "PROXY"
  description = "Reverse proxy"

  cores     = 2
  memory    = 2048
  disk_size = 8 # proxy logs rotate

  ip_address = "192.168.5.66/24"
  gateway    = "192.168.5.1"
  # n1 has vmbr0 only
  bridge = "vmbr0"

  tags = ["proxy", "opentofu"]
}

module "dhcp_box" {
  source     = "./modules/lxc"
  node_name  = "N1"
  vm_id      = 111
  hostname   = "DHCPBOX"
  cores      = 1
  ip_address = "dhcp"
}

module "templated" {
  source     = "./modules/lxc"
  node_name  = "N1"
  vm_id      = var.templated_id
  hostname   = "TEMPLATED"
  ip_address = "192.168.5.70/24"
}

resource "proxmox_virtual_environment_vm" "app" {
  node_name = "N1"
  vm_id     = 112
  name      = "APP"
  initialization {
    ip_config {
      ipv4 {
        address = "192.168.5.71/24"
      }
    }
    user_data_file_id = proxmox_virtual_environment_file.app_cloud_init.id
  }
}
''', encoding="utf-8")
    (repo / "tofu/firewall.tf").write_text('''# --- PROXY (110) ---
module "firewall_proxy" {
  source = "./modules/guest-firewall"

  node_name    = "N1"
  container_id = 110
  enabled      = true
  depends_on   = [module.proxy]

  inbound_rules = [
    { comment = "HTTPS", proto = "tcp", dport = "443" },
    # metrics, from the monitoring box only
    { comment = "Metrics", proto = "tcp", dport = "8082", source = "192.168.5.65/32", dest = "192.168.5.66/32" },
  ]

  extra_egress_rules = [
    { comment = "Backends", proto = "tcp", dport = "8080", dest = "192.168.5.0/24" },
  ]
}
''', encoding="utf-8")
    (repo / "inv/hosts.yml").write_text("all:\n  children:\n    nodes:\n      hosts:\n        n1:\n          ansible_host: 192.168.5.51\n"
                                        "    agents:\n      hosts:\n        proxy:\n    lxc:\n      hosts:\n        proxy:\n          ansible_host: 192.168.5.66\n", encoding="utf-8")
    (repo / "c.json").write_text(json.dumps({"inventory": "inv/hosts.yml", "playbooks": "pb", "roles": "roles", "node_group": "nodes"}))
    git = lambda *a: subprocess.run(["git", "-C", str(repo), *a], check=True, capture_output=True, text=True).stdout
    git("init", "-q", "-b", "main"); git("add", "."); git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "init")
    cfg = ci.load_config(repo / "c.json")
    px = {"op": "new_machine", "model": "module.proxy", "name": "GATE-2", "host": "gate-2", "description": "Second gate",
          "vm_id": 120, "node": "n1", "ip": "192.168.5.80", "rules": True, "groups": ["agents", "lxc"]}
    r = ci.apply(px, cfg, repo)
    files = {rel: new for rel, old, new in r["files"]}
    assert r["targets"] == ["module.gate_2", "module.firewall_gate_2"] and list(files) == ["tofu/main.tf", "tofu/firewall.tf", "inv/hosts.yml"], r
    m = files["tofu/main.tf"].split("# GATE-2: Second gate\n")[1]
    assert m.startswith('module "gate_2" {\n  source    = "./modules/lxc"\n  node_name = "N1"\n\n  vm_id       = 120\n  hostname    = "GATE-2"\n  description = "Second gate"\n'), m
    assert 'ip_address = "192.168.5.80/24"' in m and "disk_size = 8 # proxy logs rotate" not in m and "disk_size = 8\n" in m
    assert "# n1 has vmbr0 only" in m and 'tags = ["gate-2", "opentofu"]' in m, m
    f = files["tofu/firewall.tf"].split("# GATE-2: guest firewall\n")[1]
    assert f.startswith('module "firewall_gate_2" {') and "depends_on   = [module.gate_2]" in f and "container_id = 120" in f, f
    assert 'dest = "192.168.5.80/32"' in f and "# metrics, from the monitoring box only" in f and f.count("comment =") == 3, f
    assert "    gate-2:\n" in files["inv/hosts.yml"].split("lxc:")[1] and "ansible_host: 192.168.5.80" in files["inv/hosts.yml"].split("lxc:")[1]
    assert "ansible_host: 192.168.5.80" not in files["inv/hosts.yml"].split("lxc:")[0]  # the address where the model has its own
    # without the rules: the module call keeps its options, the lists and their comments go
    f = {rel: new for rel, old, new in ci.apply({**px, "rules": False}, cfg, repo)["files"]}["tofu/firewall.tf"].split("# GATE-2: guest firewall\n")[1]
    assert f == 'module "firewall_gate_2" {\n  source = "./modules/guest-firewall"\n\n  node_name    = "N1"\n  container_id = 120\n  enabled      = true\n  depends_on   = [module.gate_2]\n}\n', f
    # refused rather than guessed: no static address, an id that is a variable, a reference to the model's own resources
    assert "no literal address" in refused(ci.apply, {**px, "model": "module.dhcp_box"}, cfg, repo)
    assert "vm_id" in refused(ci.apply, {**px, "model": "module.templated"}, cfg, repo)
    assert "own resources (user_data_file_id" in refused(ci.apply, {**px, "model": "proxmox_virtual_environment_vm.app", "ip": "192.168.5.81"}, cfg, repo)
    # tofu fmt agrees with the generated HCL, when tofu is installed
    if shutil.which("tofu"):
        for rel, new in files.items():
            if rel.endswith(".tf"):
                (repo / rel).write_text(new, encoding="utf-8", newline="\n")
        fmt = subprocess.run(["tofu", "fmt", "-check", "-diff", str(repo / "tofu")], capture_output=True, text=True)
        assert fmt.returncode == 0, fmt.stdout + fmt.stderr

assert ci.favicon().startswith(b"\x89PNG")  # served at /favicon.ico
print("ok")
