"""Read-only candidate deployment contract for production admission.

Nothing here installs files or treats checkout ownership as authority. The
operator must provision the fixed root-owned tree and invoke its Python with
``-I -S`` and an explicit fixed ops import path. Missing deployment fails closed.
Root administrators (including their standard-library installation) are trusted;
callers, their environment, checkout and JSON are not.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
import stat
import sys

import sixlab_jit_pr_runner_bridge as bridge
import sixlab_jit_launcher_generator as generator


MANIFEST = Path("/etc/opcb/sixlab-jit-python-trust-v1.json")
SCHEMA = "opcb-sixlab-jit-python-trust-v1"
OPS_ROOT = Path("/var/lib/opcb/sixlab-jit/projectmanager/ops")
KEY_PATH = Path("/etc/opcb/sixlab-jit-readonly-ssh-key")
KNOWN_HOSTS_PATH = Path("/etc/opcb/sixlab-jit-known-hosts")
MODULES = frozenset({
    "sixlab_jit_trusted_deployment", "sixlab_jit_trusted_cycle",
    "sixlab_jit_actuator_admission", "sixlab_jit_pr_runner_bridge",
    "sixlab_jit_shadow_collector", "sixlab_jit_shadow_controller",
    "sixlab_jit_shadow_inventory", "sixlab_jit_serial_scheduler",
    "sixlab_jit_launcher_generator", "sixlab_jit_safe_input",
})
_DIGEST = re.compile(r"^[0-9a-f]{64}$")


def _fail(message: str) -> None:
    raise bridge.BridgeError("trusted Python deployment: " + message)


def _entry(value: object, label: str, fixed: Path | None = None) -> tuple[Path, str]:
    if not isinstance(value, dict) or set(value) != {"path", "sha256"}:
        _fail(label + " fields are invalid")
    path, digest = value["path"], value["sha256"]
    if (not isinstance(path, str) or not path.startswith("/")
            or str(Path(path)) != path or ".." in Path(path).parts
            or not isinstance(digest, str) or not _DIGEST.fullmatch(digest)
            or (fixed is not None and path != str(fixed))):
        _fail(label + " binding is invalid")
    return Path(path), digest


def _interpreter_origins(python: bridge._VerifiedFile) -> None:
    if not sys.flags.isolated or not sys.flags.no_site:
        _fail("requires isolated Python -I -S")
    if sys.executable != str(python.path):
        _fail("executing Python differs from pinned executable")
    if getattr(sys.modules.get("__main__"), "__file__", None) != str(
            OPS_ROOT / "sixlab_jit_actuator_admission.py"):
        _fail("entrypoint is outside installed closure")
    # A Python zip entry may be configured but absent. Reject such a deployment
    # instead of silently blessing a future import location not verified today.
    for entry in sys.path:
        if not isinstance(entry, str) or not entry or not Path(entry).is_absolute():
            _fail("unsafe Python import path")
        bridge._root_owned_safe_path(Path(entry), "Python import path")
    for name, module in tuple(sys.modules.items()):
        if module is None:
            continue
        origin = getattr(module, "__file__", None)
        spec = getattr(module, "__spec__", None)
        spec_origin = getattr(spec, "origin", None)
        if name in MODULES:
            expected = str(OPS_ROOT / (name + ".py"))
            if origin != expected or spec_origin != expected:
                _fail("loaded module origin drifted: " + name)
        elif name == "__main__" and origin is not None:
            if origin != str(OPS_ROOT / "sixlab_jit_actuator_admission.py"):
                _fail("entrypoint is outside installed closure")
        elif origin is not None:
            # Standard-library and extension origins must also be root safe.
            bridge._root_owned_safe_path(Path(origin), "loaded Python dependency")
        elif spec_origin not in ("built-in", "frozen") and name != "__main__":
            _fail("loaded Python dependency has no verifiable origin: " + name)


class Runtime:
    def __init__(self, files: dict[str, bridge._VerifiedFile],
                 node: bridge._VerifiedFile, vendor: bridge._InstalledVendor) -> None:
        self._files = files
        self.node = node
        self.vendor = vendor
        self.ssh = files["ssh"]
        self.key = files["key"]
        self.known_hosts = files["known_hosts"]

    def validate(self) -> None:
        for name, verified in self._files.items():
            bridge._same_verified_file(verified, "trusted Python " + name)
        _interpreter_origins(self._files["python"])
        bridge._same_verified_file(self.node, "trusted Node executable")
        for name in self.vendor.files:
            self.vendor.executable_path(name)


def load_runtime() -> Runtime:
    """Verify fixed installation and the interpreter actually executing it."""
    manifest = bridge._verified_root_owned_file(
        MANIFEST, "Python trust manifest", None, immutable=True,
    )
    try:
        parsed = json.loads(manifest.contents)
    except (TypeError, ValueError) as error:
        raise bridge.BridgeError("Python trust manifest is invalid JSON") from error
    if (not isinstance(parsed, dict)
            or set(parsed) != {"schema", "ops_root", "modules", "python", "ssh", "key", "known_hosts"}
            or parsed["schema"] != SCHEMA or parsed["ops_root"] != str(OPS_ROOT)
            or not isinstance(parsed["modules"], dict)
            or set(parsed["modules"]) != MODULES):
        _fail("manifest fields or dependency closure are invalid")
    files = {"manifest": manifest}
    for name, fixed in (("python", None), ("ssh", None),
                        ("key", KEY_PATH), ("known_hosts", KNOWN_HOSTS_PATH)):
        path, digest = _entry(parsed[name], name, fixed)
        files[name] = bridge._verified_root_owned_file(path, name, digest)
        if name in {"python", "ssh"} and not files[name].mode & stat.S_IXUSR:
            _fail(name + " is not executable")
        if name == "key" and files[name].mode & 0o077:
            _fail("SSH private key must not be accessible to group/other")
    for name, digest in parsed["modules"].items():
        if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
            _fail("invalid module digest")
        files[name] = bridge._verified_root_owned_file(
            OPS_ROOT / (name + ".py"), "installed Python " + name, digest, immutable=True,
        )
    files["launcher_template"] = bridge._verified_root_owned_file(
        OPS_ROOT / "templates" / "pr1173-one-job-launcher-fcca0r1.sh",
        "installed launcher template", generator.TEMPLATE_SHA256, immutable=True,
    )
    if __file__ != str(OPS_ROOT / "sixlab_jit_trusted_deployment.py"):
        _fail("checkout code cannot establish production trust")
    _interpreter_origins(files["python"])
    node, vendor = bridge._trusted_runtime()
    runtime = Runtime(files, node, vendor)
    runtime.validate()
    return runtime
