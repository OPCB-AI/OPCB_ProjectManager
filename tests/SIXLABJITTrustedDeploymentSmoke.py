#!/usr/bin/env python3
"""Private fixture tests: no installed files, credentials or processes."""
import ast
import json
from pathlib import Path
import sys
import subprocess
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "ops"))
import sixlab_jit_trusted_deployment as deployment


def manifest():
    return {
        "schema": deployment.SCHEMA, "ops_root": str(deployment.OPS_ROOT),
        "modules": {name: "a" * 64 for name in deployment.MODULES},
        "python": {"path": "/usr/bin/python3", "sha256": "b" * 64},
        "ssh": {"path": "/usr/bin/ssh", "sha256": "c" * 64},
        "key": {"path": str(deployment.KEY_PATH), "sha256": "d" * 64},
        "known_hosts": {"path": str(deployment.KNOWN_HOSTS_PATH), "sha256": "e" * 64},
    }


def fail(call, expected):
    try:
        call()
    except deployment.bridge.BridgeError as error:
        assert expected in str(error), str(error)
    else:
        raise AssertionError("unsafe fixture accepted: " + expected)


def run_fixture(data, *, key_mode=0o400, ssh_mode=0o555, drift=False):
    verified = []

    def verify(path, label, expected_digest, **kwargs):
        verified.append(path)
        mode = key_mode if path == deployment.KEY_PATH else ssh_mode if label == "ssh" else 0o555
        return deployment.bridge._VerifiedFile(
            path, 1, 2, mode, 0, expected_digest or "0" * 64,
            json.dumps(data).encode() if path == deployment.MANIFEST else b"fixture",
        )

    node = verify(Path("/usr/bin/node"), "node", "f" * 64)
    vendor = SimpleNamespace(files={"fixture": node}, executable_path=lambda _: node.path)
    with patch.object(deployment.bridge, "_verified_root_owned_file", side_effect=verify), \
            patch.object(deployment.bridge, "_same_verified_file", side_effect=(
                deployment.bridge.BridgeError("identity drift") if drift else None)), \
            patch.object(deployment.bridge, "_trusted_runtime", return_value=(node, vendor)), \
            patch.object(deployment, "_interpreter_origins"), \
            patch.object(deployment, "__file__", str(deployment.OPS_ROOT / "sixlab_jit_trusted_deployment.py")):
        runtime = deployment.load_runtime()
        assert runtime.key.path == deployment.KEY_PATH
        assert runtime.known_hosts.path == deployment.KNOWN_HOSTS_PATH
        runtime.validate()
    assert deployment.OPS_ROOT / "templates" / "pr1173-one-job-launcher-fcca0r1.sh" in verified


run_fixture(manifest())
for key, value in (("schema", "other"), ("ops_root", "/tmp/ops"), ("extra", True)):
    bad = manifest()
    bad[key] = value
    fail(lambda: run_fixture(bad), "manifest fields")
bad = manifest()
bad["modules"].pop("sixlab_jit_safe_input")
fail(lambda: run_fixture(bad), "dependency closure")
bad = manifest()
bad["modules"]["sixlab_jit_safe_input"] = "bad"
fail(lambda: run_fixture(bad), "module digest")
for key, path in (("ssh", "ssh"), ("ssh", "/usr/../tmp/ssh"),
                  ("key", "/tmp/key"), ("known_hosts", "/tmp/known_hosts")):
    bad = manifest()
    bad[key]["path"] = path
    fail(lambda: run_fixture(bad), "binding is invalid")
fail(lambda: run_fixture(manifest(), key_mode=0o444), "private key")
fail(lambda: run_fixture(manifest(), ssh_mode=0o444), "not executable")
fail(lambda: run_fixture(manifest(), drift=True), "identity drift")

python = SimpleNamespace(path=Path("/usr/bin/python3"))
installed_main = str(deployment.OPS_ROOT / "sixlab_jit_actuator_admission.py")
fake_sys = SimpleNamespace(
    flags=SimpleNamespace(isolated=1, no_site=1), executable=str(python.path),
    path=[str(deployment.OPS_ROOT), "/usr/lib/python3"],
    modules={"__main__": SimpleNamespace(__file__=installed_main)},
)
with patch.object(deployment, "sys", fake_sys), \
        patch.object(deployment.bridge, "_root_owned_safe_path"):
    deployment._interpreter_origins(python)
    fake_sys.flags.isolated = 0
    fail(lambda: deployment._interpreter_origins(python), "isolated Python")
    fake_sys.flags.isolated = 1
    fake_sys.flags.no_site = 0
    fail(lambda: deployment._interpreter_origins(python), "isolated Python")
    fake_sys.flags.no_site = 1
    fake_sys.path.append("")
    fail(lambda: deployment._interpreter_origins(python), "import path")
    fake_sys.path.pop()
    fake_sys.modules["sixlab_jit_safe_input"] = SimpleNamespace(
        __file__="/tmp/evil.py", __spec__=SimpleNamespace(origin="/tmp/evil.py"))
    fail(lambda: deployment._interpreter_origins(python), "module origin drifted")
    del fake_sys.modules["sixlab_jit_safe_input"]
    fake_sys.modules["unverifiable"] = SimpleNamespace()
    fail(lambda: deployment._interpreter_origins(python), "no verifiable origin")
    del fake_sys.modules["unverifiable"]
    fake_sys.modules["__main__"].__file__ = "/tmp/caller.py"
    fail(lambda: deployment._interpreter_origins(python), "entrypoint")

# Execute the actual bootstrap AST in a real isolated interpreter. This tests
# import-path behavior, not a fictitious root installation or production trust.
source = (Path(__file__).resolve().parents[1] / "ops" / "sixlab_jit_actuator_admission.py").read_text()
bootstrap = next(node for node in ast.parse(source).body
                 if isinstance(node, ast.If) and "sys.flags.isolated" in ast.unparse(node.test))
program = "import sys,json\nfrom pathlib import Path\n" + ast.unparse(bootstrap) + "\nprint(json.dumps(sys.path))"
result = subprocess.run([sys.executable, "-I", "-S", "-c", program],
                        capture_output=True, text=True, timeout=5, check=True)
paths = json.loads(result.stdout)
assert paths[0] == str(deployment.OPS_ROOT)
assert all(path and Path(path).is_absolute() for path in paths)
assert str(Path(__file__).resolve().parents[1] / "ops") not in paths

checkout = str(Path(__file__).resolve().parents[1] / "ops")
program = f"""import sys
sys.path.insert(0, {checkout!r})
import sixlab_jit_trusted_deployment as d
def unexpected():
    raise AssertionError('credential/runtime collection reached')
d.bridge._trusted_runtime = unexpected
try:
    d.load_runtime()
except d.bridge.BridgeError:
    print('checkout rejected')
else:
    raise AssertionError('checkout accepted')
"""
result = subprocess.run([sys.executable, "-B", "-c", program],
                        capture_output=True, text=True, timeout=5, check=True)
assert result.stdout.strip() == "checkout rejected"

# Extract only imports/constants/function definitions from the real probe. No
# host observation, executable launch, SSH or credentials are performed.
import sixlab_jit_shadow_collector as collector
probe_ast = ast.parse(collector.REMOTE_PROBE)
prefix = []
for node in probe_ast.body:
    if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "services" for t in node.targets):
        break
    prefix.append(node)
probe = {}
exec(compile(ast.Module(body=prefix, type_ignores=[]), "<probe-fixture>", "exec"), probe)
try:
    probe["trusted_tool"]("caller-tool")
except RuntimeError as error:
    assert "unapproved" in str(error)
else:
    raise AssertionError("unknown remote tool accepted")
with patch.object(probe["Path"], "lstat", return_value=SimpleNamespace(st_uid=1000, st_mode=0o100755)):
    try:
        probe["trusted_tool"]("nft")
    except RuntimeError as error:
        assert "root-owned" in str(error)
    else:
        raise AssertionError("user-owned remote tool accepted")
with patch.object(probe["Path"], "lstat", return_value=SimpleNamespace(st_uid=0, st_mode=0o100777)):
    try:
        probe["trusted_tool"]("nft")
    except RuntimeError as error:
        assert "writable" in str(error)
    else:
        raise AssertionError("writable remote tool accepted")
with patch.dict(probe, trusted_tool=lambda name: "/usr/bin/" + name):
    try:
        probe["command"](["sudo", "-n", "caller-tool"])
    except RuntimeError as error:
        assert "nested" in str(error)
    else:
        raise AssertionError("unapproved sudo target accepted")
with patch.object(probe["Path"], "lstat", return_value=SimpleNamespace(st_uid=0, st_mode=0o100755)), \
        patch.object(probe["Path"], "resolve", return_value=Path("/usr/sbin/nft")):
    assert probe["trusted_tool"]("nft") == "/usr/sbin/nft"
assert probe["COMMAND_ENV"] == {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}

# Receipt ancestry cannot be a caller-owned directory even if the eventual
# descriptor names a root-owned receipt. No real host paths are opened.
with patch.object(probe["Path"], "lstat", return_value=SimpleNamespace(st_uid=1000, st_mode=0o100444)):
    try:
        probe['receipt_file']('/var/lib/sixlab-ephemeral-v1/receipts/fixture.receipt')
    except RuntimeError as error:
        assert 'root-safe' in str(error)
    else:
        raise AssertionError('untrusted receipt ancestry accepted')

# Actual FIFO/oversize reads exercise the shared root verifier, while only
# ownership checks are mocked: there is no privileged installation fixture.
import tempfile
import os
with tempfile.TemporaryDirectory() as directory:
    fifo = Path(directory) / 'fifo'
    os.mkfifo(fifo)
    large = Path(directory) / 'large'
    large.write_bytes(b'12345')
    with patch.object(deployment.bridge, '_root_owned_safe_path'), \
            patch.object(deployment.bridge, '_safe_root_metadata'), \
            patch.object(deployment.bridge, 'TRUSTED_FILE_LIMIT_BYTES', 4):
        fail(lambda: deployment.bridge._verified_root_owned_file(fifo, 'FIFO fixture', None), 'changed while')
        fail(lambda: deployment.bridge._verified_root_owned_file(large, 'large fixture', None), 'byte limit')
print("SIXLAB trusted deployment smoke: PASS (private fixtures only)")
