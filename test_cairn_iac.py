"""Smoke test on example/: python3 test_cairn_iac.py"""
import json, pathlib, tempfile, importlib.util

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("cairn_iac", HERE / "cairn-iac.py")
ci = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ci)

with tempfile.TemporaryDirectory() as tmp:
    out = pathlib.Path(tmp) / "iac.html"
    ci.build(HERE / "example/cairn-iac.json", out)
    page = out.read_text(encoding="utf-8")
    data = json.loads(page.split("const D = ")[1].split(";\n")[0])

web, db = data["tofu"]
assert (web["name"], web["kind"], web["node"], web["id"], web["cores"], web["memory"], web["disk"], web["ip"]) == \
       ("web", "LXC", "pve1", 201, "2", "2048", "16", "10.0.0.21"), web
assert (db["kind"], db["memory"], db["disk"], db["ip"]) == ("VM", "8192", "64", "10.0.0.22"), db
rules = data["firewalls"]["201"]["rules"]
assert [(r["dir"], r["dport"]) for r in rules] == [("in", "443"), ("out", "5432")], rules
assert data["playbooks"]["site"][0]["hosts"] == ["db", "pve1", "pve2", "web"]
assert data["roles"]["web"]["tasks"] == ["Install nginx", "Write the site configuration"]
assert data["roles"]["web"]["templates"] == ["site.conf.j2"]
assert data["nodes"] == ["pve1", "pve2"] and data["playbook_prefix"] == "playbooks/"
assert "<title>Example lab</title>" in page and "/*DATA*/" not in page
print("ok")
