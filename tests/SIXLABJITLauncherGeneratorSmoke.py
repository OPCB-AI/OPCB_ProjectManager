#!/usr/bin/env python3
import importlib.util
import ast
import datetime
import json
from pathlib import Path
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import time
import shutil


project = Path(__file__).resolve().parent.parent
source = project / "ops" / "sixlab_jit_launcher_generator.py"
spec = importlib.util.spec_from_file_location("generator", source)
generator = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(generator)


PULL_NUMBER = 1198
HEAD = "5589cd6e417f101244eee0b0c7f56477ff36e2a1"
SLOT = "07"
rendered, manifest = generator.render(PULL_NUMBER, HEAD, 1, SLOT)
assert manifest["rendered_sha256"] == generator._digest(rendered.encode("utf-8"))
legacy_candidate_dir = project / "artifacts" / "jit-candidates" / "pr1198"
legacy_candidate_path = legacy_candidate_dir / "pr1198-one-job-launcher-5589c-r1-usproxy5-slot07-spa-checks.sh"
legacy_manifest_path = legacy_candidate_dir / "pr1198-one-job-launcher-5589c-r1-usproxy5-slot07-spa-checks.manifest.json"
legacy_manifest = json.loads(legacy_manifest_path.read_text(encoding="utf-8"))
assert generator._digest(legacy_candidate_path.read_bytes()) == legacy_manifest["rendered_sha256"]
documentation = (project / "docs" / "sixlab-jit-shadow-controller.md").read_text(encoding="utf-8")
assert f"SHA-256 `{legacy_manifest['rendered_sha256']}`" in documentation
CURRENT_PULL_NUMBER = 1201
CURRENT_HEAD = "fe4c0c3be00a4ad264eadf6dd44ec1cf9e5f0668"
CURRENT_SLOT = "03"
current_rendered, current_manifest = generator.render(
    CURRENT_PULL_NUMBER, CURRENT_HEAD, 1, CURRENT_SLOT
)
current_candidate_dir = project / "artifacts" / "jit-candidates" / "pr1201"
current_candidate_path = current_candidate_dir / current_manifest["output_name"]
current_manifest_path = current_candidate_dir / current_manifest["manifest_name"]
assert current_candidate_path.read_text(encoding="utf-8") == current_rendered
assert json.loads(current_manifest_path.read_text(encoding="utf-8")) == current_manifest
assert current_manifest["rendered_sha256"] == generator._digest(
    current_candidate_path.read_bytes()
)
assert f"SHA-256 `{current_manifest['rendered_sha256']}`" in documentation
candidate_temp = tempfile.TemporaryDirectory(prefix="sixlab-jit-current-candidate.")
candidate_dir = Path(candidate_temp.name)
candidate_path = candidate_dir / manifest["output_name"]
candidate_manifest_path = candidate_dir / manifest["manifest_name"]
generator.write_candidate(
    pull_number=PULL_NUMBER,
    expected_head=HEAD,
    attempt=1,
    slot=SLOT,
    output=candidate_path,
    manifest_path=candidate_manifest_path,
)
assert candidate_path.read_text(encoding="utf-8") == rendered
assert json.loads(candidate_manifest_path.read_text(encoding="utf-8")) == manifest
assert manifest["pull_number"] == PULL_NUMBER
assert manifest["expected_head"] == HEAD
assert manifest["attempt"] == 1
assert manifest["slot"] == SLOT
assert manifest["family"] == "spa-checks"
assert manifest["exact_label"] == f"sixlab-pr-job-{HEAD}-spa-checks"
assert manifest["prefix"] == "5589cr1"
assert manifest["launcher_prefix"] == "5589c-r1-usproxy5-scopefd1-exitmemv5"
assert manifest["egress_profile"] == "us-proxy-v5"
assert manifest["supersedes_egress_profile"] == "us-proxy-v4"
assert manifest["upstream_proxy"] == "47.88.16.146:8443"
assert manifest["output_name"] == (
    "pr1198-one-job-launcher-5589c-r1-usproxy5-scopefd1-exitmemv5-slot07-spa-checks.sh"
)
assert manifest["manifest_name"] == (
    "pr1198-one-job-launcher-5589c-r1-usproxy5-scopefd1-exitmemv5-slot07-spa-checks.manifest.json"
)
assert manifest["capability_scope"] == "single-slot-single-family"
assert manifest["execution_evidence_profile"] == "runner-exit-scope-memory-v5"
assert manifest["legacy_receipt_schema"] == "sixlab-jit-teardown-receipt-v1"
assert manifest["sidecar_evidence_schema"] == "sixlab-jit-launcher-evidence-v5"
assert manifest["scope_memory_schema"] == "sixlab-jit-scope-memory-evidence-v5"
assert manifest["sidecar_consumer_activation"] == "not-authorized"
assert manifest["installation_authorized"] is False
assert manifest["token_mint_authorized"] is False
assert f"readonly PULL_NUMBER='{PULL_NUMBER}'" in rendered
assert f"readonly EXPECTED_HEAD='{HEAD}'" in rendered
assert "readonly ATTEMPT='1'" in rendered
assert "readonly PREFIX='5589cr1'" in rendered
assert "readonly LAUNCHER_PREFIX='5589c-r1-usproxy5-scopefd1-exitmemv5'" in rendered
assert "readonly ALLOWED_SLOT='07'" in rendered
assert "readonly ALLOWED_FAMILY='spa-checks'" in rendered
assert '[[ "${1:-}" == "$ALLOWED_SLOT" ]]' in rendered
assert "47.88.16.146" in rendered
assert "UPSTREAM_PROXY_PORT='8443'" in rendered
assert 'HTTP_PROXY="$PROXY_URL" HTTPS_PROXY="$PROXY_URL"' in rendered
assert "local relay private-target rejection failed" in rendered
assert "direct external HTTPS unexpectedly reachable" in rendered
assert 'iptables -w -A "$chain" -m comment --comment "$comment" -j DROP' in rendered
assert "--proxy-canary) [[ $# == 1 ]]" in rendered
assert "P2-R2E US proxy canary PASS" in rendered
assert "P2-R2E proxy canary teardown verification failed" in rendered
assert "P2-R2E launcher teardown verification failed" in rendered
assert "allow_reuse_address = True" in rendered
assert "receipt path already exists; archive explicitly before run" in rendered
assert "DNS_LISTEN_PORT = 15353" in rendered
assert "def dns_query_allowed(packet):" in rendered
assert "allowlist DNS relay accepted forbidden query" in rendered
assert rendered.count("type filter hook output priority filter + 10") == 2
assert "type filter hook output priority mangle + 10" not in rendered
assert "receipt path already exists; archive explicitly before run" in rendered
assert "os.O_WRONLY | os.O_CREAT | os.O_EXCL" in rendered
assert "exclusive receipt creation failed" in rendered
assert ' >"$receipt"' not in rendered
assert "stop_dedicated_runtime()" in rendered
assert "egress fence retained: dedicated runtime remains" in rendered
assert 'pkill -TERM -u "$USER_ID"' in rendered
assert 'pkill -KILL -u "$USER_ID"' in rendered
assert "class BoundedThreadingMixIn(socketserver.ThreadingMixIn):" in rendered
assert "class Server(BoundedThreadingMixIn, socketserver.TCPServer):" in rendered
assert "class DNSUDPServer(BoundedThreadingMixIn, socketserver.UDPServer):" in rendered
assert "class DNSTCPServer(BoundedThreadingMixIn, socketserver.TCPServer):" in rendered
assert rendered.count("CLIENT_GATE.acquire(blocking=False)") == 1
assert rendered.count("CLIENT_GATE.release()") == 2
assert 'pgrep -u "$USER_ID"' in rendered
assert "dedicated process exists before job admission" in rendered
assert "dedicated process exists before token exposure" in rendered
assert "getent, pkill or timeout missing for canary" in rendered
assert "getent pkill timeout" in rendered
assert "proxy canary iptables enumeration failed" in rendered
assert "proxy canary nftables enumeration failed" in rendered
assert "iptables enumeration failed" in rendered
assert "nftables enumeration failed" in rendered
assert "! iptables-save |" not in rendered
assert "! nft -a list ruleset |" not in rendered
token_read = "IFS= read -r token"
assert rendered.index('nft -f - <<NFT') < rendered.index(token_read)
assert rendered.index('iptables -w -I OUTPUT 1') < rendered.index(token_read)
assert rendered.index("dedicated process exists before token exposure") < rendered.index(token_read)
scope_invocation = 'systemd-run --user --scope --quiet --unit="$scope_unit" --property=Delegate=yes'
assert scope_invocation in rendered
assert rendered.count("systemd-run --user --scope") == 1
for incompatible_scope_option in ("--pipe", "--pty", "--wait", "--no-block"):
    assert incompatible_scope_option not in rendered
assert rendered.count("IFS= read -r token") == 1
assert rendered.index("systemd-run --user --scope") < rendered.index("IFS= read -r token")
assert "RUNNER_MANUALLY_TRAP_SIG=1 ./run.sh" in rendered
for forbidden_token_path in ("--stage-token", "--stage-existing-token", "token_path", "token_file", "registration-token", ".token"):
    assert forbidden_token_path not in rendered, forbidden_token_path
staging_attempt = subprocess.run(
    ["bash", str(candidate_path), "--stage-existing-token", SLOT],
    input="A" * 32 + "\n", capture_output=True, text=True,
)
assert staging_attempt.returncode != 0
assert "A" * 32 not in staging_attempt.stdout + staging_attempt.stderr
assert not (Path("/run") / f"sixlab-pr{PULL_NUMBER}-{manifest['prefix']}-ephemeral-{SLOT}.token").exists()

# systemd v255 rejects --pipe/--pty/--wait with --scope. Exercise the exact
# runuser -> env -> systemd-run -> env -> bash shape with a strict v255 option
# gate, then prove one stdin line reaches only the scoped payload and its exit
# status remains synchronous. This is intentionally not a permissive mock.
with tempfile.TemporaryDirectory(prefix="sixlab-systemd255-scope-stdio.") as temporary:
    root = Path(temporary)
    strict_systemd_run = root / "systemd-run"
    strict_systemd_run.write_text(
        """#!/bin/sh
set -eu
saw_user=0
saw_scope=0
saw_quiet=0
while [ \"$#\" -gt 0 ]; do
  case \"$1\" in
    --user) saw_user=1 ;;
    --scope) saw_scope=1 ;;
    --quiet) saw_quiet=1 ;;
    --property=*|--unit=*) ;;
    --pipe|--pty|--wait|--no-block) exit 93 ;;
    env) break ;;
    *) exit 94 ;;
  esac
  shift
done
[ \"$saw_user:$saw_scope:$saw_quiet\" = 1:1:1 ]
exec \"$@\"
""",
        encoding="utf-8",
    )
    strict_systemd_run.chmod(0o755)
    strict_runuser = root / "runuser"
    strict_runuser.write_text(
        """#!/bin/sh
set -eu
[ \"$1\" = -u ]
shift 2
[ \"$1\" = -- ]
shift
exec \"$@\"
""",
        encoding="utf-8",
    )
    strict_runuser.chmod(0o755)
    token_line = "B" * 32
    inherited = subprocess.run(
        [
            str(strict_runuser), "-u", "sixlabephem", "--",
            "env", "XDG_RUNTIME_DIR=/run/user/1005",
            str(strict_systemd_run), "--user", "--scope", "--quiet",
            "--unit=fixture.scope",
            "--property=Delegate=yes",
            "env", "JOB_ROOT=/run/sj02",
            "bash", "-c",
            'IFS= read -r token; if IFS= read -r extra; then exit 92; fi; '
            '[[ "$token" == "$EXPECTED_TOKEN" ]]; printf "scope-stdin-pass\\n"; exit 37',
        ],
        input=token_line + "\n",
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin", "EXPECTED_TOKEN": token_line},
    )
    assert inherited.returncode == 37, inherited.stderr
    assert inherited.stdout == "scope-stdin-pass\n"
    assert token_line not in inherited.stdout + inherited.stderr

job_cleanup = rendered.split("  cleanup() {\n", 1)[1].split("\n  }\n", 1)[0]
assert "status=70" in job_cleanup
assert "(( status != 0 )) || status=70" in job_cleanup
assert "(( status != 0 )) || status=75" in job_cleanup
assert job_cleanup.index("if stop_dedicated_runtime; then") < job_cleanup.index(
    'iptables -w -D OUTPUT'
)
assert job_cleanup.index("if stop_dedicated_runtime; then") < job_cleanup.index(
    'nft delete table inet "$nft_table"'
)
canary_cleanup = rendered.split("  cleanup_canary() {\n", 1)[1].split("\n  }\n", 1)[0]
assert canary_cleanup.index("if stop_dedicated_runtime; then") < canary_cleanup.index(
    'iptables -w -D OUTPUT'
)
for signal_trap in (
    "trap 'cleanup_canary 129' HUP",
    "trap 'cleanup_canary 130' INT",
    "trap 'cleanup_canary 143' TERM",
    "trap 'cleanup 129' HUP",
    "trap 'cleanup 130' INT",
    "trap 'cleanup 143' TERM",
    'trap "cleanup_inner 129" HUP',
    'trap "cleanup_inner 130" INT',
    'trap "cleanup_inner 143" TERM',
):
    assert signal_trap in rendered
assert rendered.count("curl -4 -fsSI -o /dev/null") == 2
assert "tcp dport { 53, 80, 443 } accept" not in rendered
assert "amazonaws.com" not in rendered
assert "blob.core.windows.net" not in rendered
assert "meta skuid $USER_ID udp dport 53 accept" not in rendered
assert "meta skuid $USER_ID tcp dport 53 accept" not in rendered
assert "ip daddr { 183.60.83.19, 183.60.82.98 }" not in rendered
assert '-d "$resolver" -p udp --dport 53' not in rendered
assert '-d "$resolver" -p tcp --dport 53' not in rendered
assert rendered.count('REDIRECT --to-ports "$LOCAL_DNS_PORT"') == 4
assert rendered.count("\n  jump_created=1\n") == 2
assert rendered.count("dns_jump_created=1") == 2
assert rendered.count('grep -Fq ":$chain "') == 3
assert rendered.count('grep -Fq -- "-j $chain"') == 2
assert rendered.count('if (( signal_status != 0 )); then') == 3

with tempfile.TemporaryDirectory(prefix="sixlab-jit-launcher.") as temporary:
    root = Path(temporary)
    output = root / manifest["output_name"]
    manifest_path = root / manifest["manifest_name"]
    written = generator.write_candidate(
        pull_number=PULL_NUMBER,
        expected_head=HEAD,
        attempt=1,
        slot=SLOT,
        output=output,
        manifest_path=manifest_path,
    )
    assert output.stat().st_mode & 0o777 == 0o755
    assert manifest_path.stat().st_mode & 0o777 == 0o600
    assert json.loads(manifest_path.read_text()) == written
    syntax = subprocess.run(
        ["/bin/bash", "-n", str(output)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert syntax.returncode == 0, syntax.stderr
    wrong_name = root / "generic-launcher.sh"
    try:
        generator.write_candidate(
            pull_number=PULL_NUMBER,
            expected_head=HEAD,
            attempt=1,
            slot=SLOT,
            output=wrong_name,
            manifest_path=root / manifest["manifest_name"],
        )
    except generator.GeneratorError as error:
        assert "filename" in str(error)
    else:
        raise AssertionError("generic output filename was accepted")
    same_path = root / manifest["output_name"]
    try:
        generator.write_candidate(
            pull_number=PULL_NUMBER,
            expected_head=HEAD,
            attempt=1,
            slot=SLOT,
            output=same_path,
            manifest_path=same_path,
        )
    except generator.GeneratorError as error:
        assert "paths must differ" in str(error)
    else:
        raise AssertionError("identical candidate and manifest paths were accepted")
    original_launcher = output.read_bytes()
    original_manifest = manifest_path.read_bytes()
    try:
        generator.write_candidate(
            pull_number=PULL_NUMBER,
            expected_head=HEAD,
            attempt=1,
            slot=SLOT,
            output=output,
            manifest_path=manifest_path,
        )
    except generator.GeneratorError as error:
        assert "already exists" in str(error)
    else:
        raise AssertionError("immutable candidate was overwritten")
    assert output.read_bytes() == original_launcher
    assert manifest_path.read_bytes() == original_manifest

source_rendered, source_manifest = generator.render(
    generator.SOURCE_PULL_NUMBER,
    generator.SOURCE_HEAD,
    generator.SOURCE_ATTEMPT,
    generator.SOURCE_SLOT,
)
assert source_manifest["expected_head"] == generator.SOURCE_HEAD
assert f"readonly EXPECTED_HEAD='{generator.SOURCE_HEAD}'" in source_rendered

try:
    generator.render(PULL_NUMBER, "not-a-sha", 1, SLOT)
except generator.GeneratorError as error:
    assert "40-hex" in str(error)
else:
    raise AssertionError("invalid head was accepted")

try:
    generator.render(0, HEAD, 1, SLOT)
except generator.GeneratorError as error:
    assert "pull number" in str(error)
else:
    raise AssertionError("invalid pull number was accepted")

try:
    generator.render(PULL_NUMBER, HEAD, 1, "08")
except generator.GeneratorError as error:
    assert "slot" in str(error)
else:
    raise AssertionError("invalid slot was accepted")

text = source.read_text(encoding="utf-8")
for forbidden in (
    "subprocess",
    "ssh",
    "scp",
    "systemctl",
    "gh api",
):
    assert forbidden not in text, forbidden


scope_collector_source = rendered.split(
    "# SIXLAB_SCOPE_MEMORY_COLLECTOR_BEGIN\n", 1
)[1].split("# SIXLAB_SCOPE_MEMORY_COLLECTOR_END", 1)[0]
compile(scope_collector_source, "scope-memory-collector.py", "exec")


def create_scope_fixture(root, *, membership=None, uid=1005, bad_current=False):
    proc_root = root / "proc"
    cgroup_root = root / "cgroup"
    proc_pid = proc_root / "4242"
    proc_pid.mkdir(parents=True)
    scope_membership = membership or (
        "/user.slice/user-1005.slice/user@1005.service/app.slice/fixture.scope"
    )
    (proc_pid / "status").write_text(
        f"Name:\tfixture\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n",
        encoding="ascii",
    )
    (proc_pid / "cgroup").write_text(f"0::{scope_membership}\n", encoding="ascii")
    (proc_pid / "environ").write_bytes(b"TOKEN=SECRET_SENTINEL_DO_NOT_LEAK\0")
    (proc_pid / "cmdline").write_bytes(b"SECRET_SENTINEL_DO_NOT_LEAK\0--token\0")
    expected_listener = root / "expected-runner-listener"
    expected_listener.write_bytes(b"verified Runner.Listener fixture\n")
    expected_listener.chmod(0o755)
    (proc_pid / "exe").symlink_to(expected_listener)
    scope_root = cgroup_root / scope_membership.lstrip("/")
    scope_root.mkdir(parents=True)
    (scope_root / "memory.current").write_text(
        "not-an-integer\n" if bad_current else "1048576\n", encoding="ascii"
    )
    (scope_root / "memory.peak").write_text("2097152\n", encoding="ascii")
    events = "low 0\nhigh 2\nmax 3\noom 1\noom_kill 0\noom_group_kill 0\n"
    (scope_root / "memory.events").write_text(events, encoding="ascii")
    (scope_root / "memory.events.local").write_text(events, encoding="ascii")
    (scope_root / "memory.pressure").write_text(
        "some avg10=0.01 avg60=0.02 avg300=0.03 total=123\n"
        "full avg10=0.00 avg60=0.00 avg300=0.00 total=7\n",
        encoding="ascii",
    )
    return proc_root, cgroup_root, proc_pid, scope_root


def collector_arguments(collector, output, stop, proc_root, cgroup_root):
    expected_listener = proc_root.parent / "expected-runner-listener"
    expected_identity = expected_listener.stat()
    return [
        sys.executable,
        str(collector),
        str(output),
        str(stop),
        "1005",
        "fixture.scope",
        str(proc_root),
        str(cgroup_root),
        str(expected_identity.st_dev),
        str(expected_identity.st_ino),
        "100",
        "10",
    ]


with tempfile.TemporaryDirectory(prefix="sixlab-scope-memory.") as temporary:
    root = Path(temporary)
    collector = root / "collector.py"
    collector.write_text(scope_collector_source, encoding="utf-8")

    normal = root / "normal"
    proc_root, cgroup_root, _proc_pid, _scope_root = create_scope_fixture(normal)
    stop = normal / "stop"
    stop.write_text("", encoding="ascii")
    output = normal / "evidence.json"
    collected = subprocess.run(
        collector_arguments(collector, output, stop, proc_root, cgroup_root),
        check=False,
        capture_output=True,
        text=True,
    )
    assert collected.returncode == 0, (
        collected.returncode,
        collected.stdout,
        collected.stderr,
        output.read_text(encoding="ascii"),
    )
    memory_evidence = json.loads(output.read_text(encoding="ascii"))
    assert memory_evidence["collection_status"] == "observed"
    assert memory_evidence["runner_listener_observed"] is True
    assert memory_evidence["sample"]["pids"] == [4242]
    assert memory_evidence["sample"]["memory_current_bytes"] == 1048576
    assert memory_evidence["sample"]["memory_peak_bytes"] == 2097152
    assert memory_evidence["sample"]["memory_events"]["oom"] == 1
    assert memory_evidence["sample"]["memory_pressure"]["some"]["total"] == 123
    assert "SECRET_SENTINEL_DO_NOT_LEAK" not in output.read_text(encoding="ascii")

    fake_named = root / "fake-named-listener"
    fake_proc, fake_cgroup, fake_pid, _ = create_scope_fixture(fake_named)
    (fake_pid / "exe").unlink()
    unrelated_directory = fake_named / "unrelated"
    unrelated_directory.mkdir()
    unrelated_listener = unrelated_directory / "Runner.Listener"
    unrelated_listener.write_bytes(b"unrelated executable with matching basename\n")
    unrelated_listener.chmod(0o755)
    (fake_pid / "exe").symlink_to(unrelated_listener)
    fake_stop = fake_named / "stop"
    fake_stop.write_text("", encoding="ascii")
    fake_output = fake_named / "evidence.json"
    fake_collection = subprocess.run(
        collector_arguments(collector, fake_output, fake_stop, fake_proc, fake_cgroup),
        check=False,
        capture_output=True,
        text=True,
    )
    assert fake_collection.returncode == 75
    fake_evidence = json.loads(fake_output.read_text(encoding="ascii"))
    assert fake_evidence["collection_status"] == "unknown"
    assert fake_evidence["reason"] == "runner_listener_not_observed"

    vanished = root / "vanished"
    vanished_proc, vanished_cgroup, vanished_pid, _ = create_scope_fixture(vanished)
    vanished_output = vanished / "evidence.json"
    process = subprocess.Popen(
        collector_arguments(
            collector, vanished_output, vanished / "stop", vanished_proc, vanished_cgroup
        ),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    time.sleep(0.15)
    shutil.rmtree(vanished_pid)
    stdout, stderr = process.communicate(timeout=5)
    assert process.returncode == 0, (stdout, stderr)
    vanished_evidence = json.loads(vanished_output.read_text(encoding="ascii"))
    assert vanished_evidence["reason"] == "scope_disappeared_after_observation"
    assert vanished_evidence["sample_count"] >= 1

    wrong_binding = root / "wrong-binding"
    wrong_proc, wrong_cgroup, _wrong_pid, _ = create_scope_fixture(
        wrong_binding,
        membership="/user.slice/user-1005.slice/user@1005.service/app.slice/wrong.scope",
    )
    wrong_stop = wrong_binding / "stop"
    wrong_stop.write_text("", encoding="ascii")
    wrong_output = wrong_binding / "evidence.json"
    rejected = subprocess.run(
        collector_arguments(collector, wrong_output, wrong_stop, wrong_proc, wrong_cgroup),
        check=False,
        capture_output=True,
        text=True,
    )
    assert rejected.returncode == 75
    assert json.loads(wrong_output.read_text())["collection_status"] == "unknown"

    wrong_uid = root / "wrong-uid"
    uid_proc, uid_cgroup, _uid_pid, _ = create_scope_fixture(wrong_uid, uid=1006)
    uid_stop = wrong_uid / "stop"
    uid_stop.write_text("", encoding="ascii")
    uid_output = wrong_uid / "evidence.json"
    rejected = subprocess.run(
        collector_arguments(collector, uid_output, uid_stop, uid_proc, uid_cgroup),
        check=False,
        capture_output=True,
        text=True,
    )
    assert rejected.returncode == 75
    assert json.loads(uid_output.read_text())["collection_status"] == "unknown"

    failed = root / "failed"
    failed_proc, failed_cgroup, _failed_pid, _ = create_scope_fixture(
        failed, bad_current=True
    )
    failed_stop = failed / "stop"
    failed_stop.write_text("", encoding="ascii")
    failed_output = failed / "evidence.json"
    failed_collection = subprocess.run(
        collector_arguments(
            collector, failed_output, failed_stop, failed_proc, failed_cgroup
        ),
        check=False,
        capture_output=True,
        text=True,
    )
    assert failed_collection.returncode == 75
    assert json.loads(failed_output.read_text())["reason"] == "collector_error"

    symlinked = root / "symlinked"
    symlink_proc, symlink_cgroup, _symlink_pid, symlink_scope = create_scope_fixture(
        symlinked
    )
    real_scope = symlinked / "real-scope"
    symlink_scope.rename(real_scope)
    symlink_scope.symlink_to(real_scope, target_is_directory=True)
    symlink_stop = symlinked / "stop"
    symlink_stop.write_text("", encoding="ascii")
    symlink_output = symlinked / "evidence.json"
    symlink_collection = subprocess.run(
        collector_arguments(
            collector, symlink_output, symlink_stop, symlink_proc, symlink_cgroup
        ),
        check=False,
        capture_output=True,
        text=True,
    )
    assert symlink_collection.returncode == 75
    assert json.loads(symlink_output.read_text())["reason"] == "collector_error"

    oversized = root / "oversized"
    oversized_proc, oversized_cgroup, _oversized_pid, oversized_scope = create_scope_fixture(
        oversized
    )
    (oversized_scope / "memory.current").write_text("1" * 4097, encoding="ascii")
    oversized_stop = oversized / "stop"
    oversized_stop.write_text("", encoding="ascii")
    oversized_output = oversized / "evidence.json"
    oversized_collection = subprocess.run(
        collector_arguments(
            collector, oversized_output, oversized_stop, oversized_proc, oversized_cgroup
        ),
        check=False,
        capture_output=True,
        text=True,
    )
    assert oversized_collection.returncode == 75
    assert json.loads(oversized_output.read_text())["reason"] == "collector_error"
    assert "(before.st_dev, before.st_ino)" in scope_collector_source

    receipt_writer_source = rendered.split("<<'RECEIPT_PY' || writer_exit=$?\n", 1)[1].split(
        "\nRECEIPT_PY", 1
    )[0]
    compile(receipt_writer_source, "exclusive-receipt-writer.py", "exec")
    receipt_writer = root / "writer.py"
    receipt_writer.write_text(receipt_writer_source, encoding="utf-8")

    def write_pair(
        name, telemetry, controller_status, controller_exit, teardown_exit, final_exit,
        expected_writer_exit=None, stop_override=None, refresh_observed=True,
        pre_run_delay=0, symlink_telemetry=False, preexisting_receipt=None,
        writer_override=None,
    ):
        receipt_path = root / f"{name}.receipt"
        evidence_path = root / f"{name}.evidence-v5.json"
        telemetry_input = root / f"{name}.memory-evidence.json"
        if telemetry.exists():
            if symlink_telemetry:
                telemetry_input.symlink_to(telemetry)
            else:
                shutil.copyfile(telemetry, telemetry_input)
                telemetry_value = json.loads(telemetry_input.read_text(encoding="ascii"))
                if refresh_observed and telemetry_value["collection_status"] == "observed":
                    telemetry_value["sample"]["captured_at"] = datetime.datetime.now(
                        datetime.timezone.utc
                    ).isoformat().replace("+00:00", "Z")
                    telemetry_value["last_sample_age_ms"] = 0
                    telemetry_input.write_text(json.dumps(telemetry_value), encoding="ascii")
        stop_path = root / f"{name}.memory-evidence.stop"
        stop_path.write_text("", encoding="ascii")
        if stop_override is not None:
            stop_path = stop_override
        if preexisting_receipt is not None:
            receipt_path.write_bytes(preexisting_receipt)
        arguments = [
            sys.executable,
            str(writer_override or receipt_writer),
            str(receipt_path),
            str(evidence_path),
            str(telemetry_input),
            str(stop_path),
            "07",
            "sixlab-pr1198-5589cr1-07",
            HEAD,
            f"sixlab-pr-job-{HEAD}-spa-checks",
            "fixture.scope",
            controller_status,
            str(controller_exit),
            str(teardown_exit),
            str(final_exit),
            "2026-09-03T14:00:00+00:00",
        ]
        if pre_run_delay:
            time.sleep(pre_run_delay)
        completed = subprocess.run(arguments, check=False, capture_output=True, text=True)
        if expected_writer_exit is None:
            expected_writer_exit = final_exit
        assert completed.returncode == expected_writer_exit, completed.stderr
        if receipt_path.exists() and not symlink_telemetry:
            assert not telemetry_input.exists()
            if stop_override is None:
                assert not stop_path.exists()
        return receipt_path, evidence_path, arguments

    receipt_path, evidence_path, arguments = write_pair("normal", output, "exited", 0, 0, 0)
    normal_evidence = json.loads(evidence_path.read_text(encoding="ascii"))
    assert normal_evidence["schema"] == "sixlab-jit-launcher-evidence-v5"
    assert normal_evidence["runner"] == {
        "status": "listener_observed_exit_unknown",
        "exit_code": None,
    }
    assert normal_evidence["controller"] == {"status": "exited", "exit_code": 0}
    assert normal_evidence["teardown"] == {"status": "ok", "exit_code": 0}
    assert normal_evidence["telemetry_cleanup"] == {"status": "ok", "exit_code": 0}
    assert receipt_path.read_text().split()[4] == "exit=0"
    assert receipt_path.stat().st_mode & 0o777 == 0o444
    assert evidence_path.stat().st_mode & 0o777 == 0o444
    original_receipt = receipt_path.read_bytes()
    collision = subprocess.run(arguments, check=False, capture_output=True, text=True)
    assert collision.returncode != 0
    assert receipt_path.read_bytes() == original_receipt

    unverified_listener = root / "unverified-listener-source.json"
    unverified_listener_value = json.loads(json.dumps(memory_evidence))
    unverified_listener_value["runner_listener_observed"] = False
    unverified_listener_value["sample"]["runner_listener_pids"] = []
    unverified_listener.write_text(json.dumps(unverified_listener_value), encoding="ascii")
    unverified_receipt, unverified_evidence_path, _ = write_pair(
        "unverified-listener", unverified_listener, "exited", 0, 0, 0,
        expected_writer_exit=75,
    )
    unverified_evidence = json.loads(unverified_evidence_path.read_text(encoding="ascii"))
    assert unverified_evidence["memory"]["reason"] == "collector_result_missing_or_invalid"
    assert "exit=75" in unverified_receipt.read_text()

    abnormal_receipt, abnormal_evidence_path, _ = write_pair(
        "abnormal", output, "exited", 134, 0, 134
    )
    abnormal_evidence = json.loads(abnormal_evidence_path.read_text())
    assert abnormal_evidence["runner"] == {
        "status": "listener_observed_exit_unknown",
        "exit_code": None,
    }
    assert abnormal_evidence["controller"]["exit_code"] == 134
    assert "exit=134" in abnormal_receipt.read_text()

    signal_receipt, signal_evidence_path, _ = write_pair(
        "signal", output, "interrupted", 143, 0, 143
    )
    signal_evidence = json.loads(signal_evidence_path.read_text())
    assert signal_evidence["runner"] == {
        "status": "interrupted_unknown",
        "exit_code": None,
    }
    assert signal_evidence["controller"]["exit_code"] == 143
    assert "exit=143" in signal_receipt.read_text()

    teardown_receipt, teardown_evidence_path, _ = write_pair(
        "teardown", output, "exited", 0, 70, 70
    )
    teardown_evidence = json.loads(teardown_evidence_path.read_text())
    assert teardown_evidence["teardown"] == {"status": "failed", "exit_code": 70}
    assert "exit=70" in teardown_receipt.read_text()

    unknown_receipt, unknown_evidence_path, _ = write_pair(
        "unknown", failed_output, "exited", 0, 0, 75
    )
    unknown_evidence = json.loads(unknown_evidence_path.read_text())
    assert unknown_evidence["memory"]["collection_status"] == "unknown"
    assert "exit=75" in unknown_receipt.read_text()

    invalid_receipt, invalid_evidence_path, _ = write_pair(
        "invalid", root / "missing-telemetry.json", "exited", 0, 0, 0,
        expected_writer_exit=75,
    )
    invalid_evidence = json.loads(invalid_evidence_path.read_text())
    assert invalid_evidence["memory"]["reason"] == "collector_result_missing_or_invalid"
    assert invalid_evidence["final_exit_code"] == 75
    assert "exit=75" in invalid_receipt.read_text()

    stale = root / "stale-source.json"
    stale_value = json.loads(json.dumps(memory_evidence))
    stale_value["last_sample_age_ms"] = 2001
    stale.write_text(json.dumps(stale_value), encoding="ascii")
    stale_receipt, stale_evidence_path, _ = write_pair(
        "stale", stale, "exited", 0, 0, 0, expected_writer_exit=75,
        refresh_observed=False,
    )
    stale_evidence = json.loads(stale_evidence_path.read_text())
    assert stale_evidence["memory"]["reason"] == "stale_sample"
    assert stale_evidence["runner"] == {"status": "not_observed", "exit_code": None}
    assert "exit=75" in stale_receipt.read_text()

    aged_receipt, aged_evidence_path, _ = write_pair(
        "aged-during-teardown", output, "exited", 0, 0, 0,
        expected_writer_exit=75, pre_run_delay=2.1,
    )
    aged_evidence = json.loads(aged_evidence_path.read_text())
    assert aged_evidence["memory"]["reason"] == "stale_sample"
    assert aged_evidence["memory"]["last_sample_age_ms"] >= 2000
    assert aged_evidence["runner"] == {"status": "not_observed", "exit_code": None}
    assert "exit=75" in aged_receipt.read_text()

    slow_writer = root / "slow-staging-writer.py"
    slow_writer.write_text(
        receipt_writer_source.replace(
            "        os.fsync(descriptor)\n",
            "        __import__('time').sleep(1.1)\n        os.fsync(descriptor)\n",
            1,
        ),
        encoding="utf-8",
    )
    staged_stale_receipt, staged_stale_evidence_path, _ = write_pair(
        "aged-during-publication-staging", output, "exited", 0, 0, 0,
        expected_writer_exit=75, writer_override=slow_writer,
    )
    staged_stale_evidence = json.loads(staged_stale_evidence_path.read_text())
    assert staged_stale_evidence["memory"]["reason"] == "stale_sample"
    assert staged_stale_evidence["runner"] == {"status": "not_observed", "exit_code": None}
    assert "exit=75" in staged_stale_receipt.read_text()

    cleanup_directory = root / "cleanup-directory"
    cleanup_directory.mkdir()
    cleanup_receipt, cleanup_evidence_path, _ = write_pair(
        "cleanup-failure", output, "exited", 0, 0, 0,
        expected_writer_exit=74, stop_override=cleanup_directory,
    )
    cleanup_evidence = json.loads(cleanup_evidence_path.read_text())
    assert cleanup_evidence["telemetry_cleanup"] == {"status": "failed", "exit_code": 74}
    assert cleanup_evidence["final_exit_code"] == 74
    assert "exit=74" in cleanup_receipt.read_text()

    rollback_marker = b"existing-receipt-must-survive\n"
    rollback_receipt, rollback_evidence_path, _ = write_pair(
        "receipt-collision-rollback", output, "exited", 0, 0, 0,
        expected_writer_exit=1, preexisting_receipt=rollback_marker,
    )
    assert rollback_receipt.read_bytes() == rollback_marker
    assert not rollback_evidence_path.exists()

    oversized_telemetry = root / "oversized-telemetry-source.json"
    oversized_telemetry.write_bytes(b"{" + b" " * 16384 + b"}")
    oversized_receipt, oversized_evidence_path, _ = write_pair(
        "oversized-telemetry", oversized_telemetry, "exited", 0, 0, 0,
        expected_writer_exit=75, refresh_observed=False,
    )
    assert json.loads(oversized_evidence_path.read_text())["memory"]["reason"] == (
        "collector_result_missing_or_invalid"
    )

    symlink_receipt, symlink_evidence_path, _ = write_pair(
        "symlink-telemetry", output, "exited", 0, 0, 75,
        expected_writer_exit=75, refresh_observed=False, symlink_telemetry=True,
    )
    assert json.loads(symlink_evidence_path.read_text())["memory"]["reason"] == (
        "collector_result_missing_or_invalid"
    )

    writer_tree = ast.parse(receipt_writer_source)
    identity_tree = ast.Module(
        body=[
            node for node in writer_tree.body
            if isinstance(node, (ast.Import, ast.ImportFrom))
            or isinstance(node, ast.FunctionDef) and node.name == "read_telemetry"
        ],
        type_ignores=[],
    )
    identity_namespace = {"scope_unit": "fixture.scope"}
    exec(compile(identity_tree, "writer-read-telemetry.py", "exec"), identity_namespace)
    identity_source = root / "identity-source.json"
    identity_source.write_text(json.dumps(memory_evidence), encoding="ascii")
    identity_replacement = root / "identity-replacement.json"
    identity_replacement.write_text(json.dumps(memory_evidence), encoding="ascii")
    identity_retired = root / "identity-retired.json"
    real_os = identity_namespace["os"]

    class SwapBeforeOpen:
        def __getattr__(self, name):
            return getattr(real_os, name)

        def open(self, path, flags, *args):
            identity_source.rename(identity_retired)
            identity_replacement.rename(identity_source)
            return real_os.open(path, flags, *args)

    identity_namespace["os"] = SwapBeforeOpen()
    try:
        identity_namespace["read_telemetry"](identity_source)
    except ValueError as error:
        assert str(error) == "telemetry identity drift"
    else:
        raise AssertionError("telemetry inode replacement was accepted")


with tempfile.TemporaryDirectory(prefix="sixlab-runner-exit-fixture.") as temporary:
    root = Path(temporary)
    fake_run = root / "run.sh"
    fake_run.write_text(
        "#!/bin/bash\n"
        "if [[ -n \"${RUNNER_MANUALLY_TRAP_SIG:-}\" ]]; then exit \"$FAKE_EXIT\"; fi\n"
        "exit 0\n",
        encoding="utf-8",
    )
    fake_run.chmod(0o755)
    for expected in (0, 134):
        propagated = subprocess.run(
            ["bash", "-c", "RUNNER_MANUALLY_TRAP_SIG=1 ./run.sh"],
            cwd=root,
            env={"PATH": "/usr/bin:/bin", "FAKE_EXIT": str(expected)},
            check=False,
        )
        assert propagated.returncode == expected
    signaled = subprocess.run(
        ["bash", "-c", "trap 'exit 143' TERM; kill -TERM $$"], check=False
    )
    assert signaled.returncode == 143


relay_source = rendered.split("# SIXLAB_US_PROXY_RELAY_BEGIN\n", 1)[1].split(
    "# SIXLAB_US_PROXY_RELAY_END", 1
)[0]
compile(relay_source, "embedded-us-proxy-relay.py", "exec")


class FakeUpstream(socketserver.ThreadingTCPServer):
    allow_reuse_address = False
    daemon_threads = True


upstream_requests: list[bytes] = []


class FakeUpstreamHandler(socketserver.BaseRequestHandler):
    def handle(self):
        raw = b""
        while b"\r\n\r\n" not in raw:
            chunk = self.request.recv(4096)
            if not chunk:
                return
            raw += chunk
        upstream_requests.append(raw)
        self.request.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
        while True:
            data = self.request.recv(4096)
            if not data:
                return
            self.request.sendall(data)


class FakeDNSUpstream(socketserver.ThreadingUDPServer):
    allow_reuse_address = False
    daemon_threads = True


dns_requests: list[bytes] = []


class FakeDNSUpstreamHandler(socketserver.BaseRequestHandler):
    def handle(self):
        packet, stream = self.request
        dns_requests.append(packet)
        flags = struct.unpack("!H", packet[2:4])[0]
        response_flags = 0x8000 | (flags & 0x0100) | 0x0080
        response = packet[:2] + struct.pack("!HHHHH", response_flags, 1, 0, 0, 0) + packet[12:]
        stream.sendto(response, self.client_address)


def dns_query(name: str, transaction: int) -> bytes:
    labels = b"".join(bytes([len(part)]) + part.encode("ascii") for part in name.split("."))
    return struct.pack("!HHHHHH", transaction, 0x0100, 1, 0, 0, 0) + labels + b"\x00" + struct.pack("!HH", 1, 1)


def free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


with FakeUpstream(("127.0.0.1", 0), FakeUpstreamHandler) as upstream, \
        FakeDNSUpstream(("127.0.0.1", 0), FakeDNSUpstreamHandler) as dns_upstream:
    upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    dns_upstream_thread = threading.Thread(target=dns_upstream.serve_forever, daemon=True)
    upstream_thread.start()
    dns_upstream_thread.start()
    relay_port = free_port()
    dns_port = free_port()
    upstream_port = int(upstream.server_address[1])
    dns_upstream_port = int(dns_upstream.server_address[1])
    test_source = relay_source.replace(
        'LISTEN_PORT = 18080', f'LISTEN_PORT = {relay_port}', 1
    ).replace(
        'UPSTREAM_HOST = "47.88.16.146"', 'UPSTREAM_HOST = "127.0.0.1"', 1
    ).replace(
        'UPSTREAM_PORT = 8443', f'UPSTREAM_PORT = {upstream_port}', 1
    ).replace(
        'DNS_LISTEN_PORT = 15353', f'DNS_LISTEN_PORT = {dns_port}', 1
    ).replace(
        'DNS_RESOLVERS = ("183.60.83.19", "183.60.82.98")', 'DNS_RESOLVERS = ("127.0.0.1",)', 1
    ).replace(
        'DNS_UPSTREAM_PORT = 53', f'DNS_UPSTREAM_PORT = {dns_upstream_port}', 1
    )
    with tempfile.TemporaryDirectory(prefix="sixlab-us-relay.") as temporary:
        relay_path = Path(temporary) / "relay.py"
        relay_path.write_text(test_source, encoding="utf-8")
        def start_relay() -> subprocess.Popen[str]:
            return subprocess.Popen(
                [sys.executable, str(relay_path)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
            )

        def wait_for_relay(process: subprocess.Popen[str]) -> None:
            for _ in range(80):
                try:
                    with socket.create_connection(("127.0.0.1", relay_port), timeout=0.1), \
                            socket.create_connection(("127.0.0.1", dns_port), timeout=0.1):
                        return
                except OSError:
                    if process.poll() is not None:
                        break
                    time.sleep(0.025)
            stderr = process.stderr.read() if process.stderr is not None else ""
            raise AssertionError(f"embedded relay did not start: {stderr}")

        def stop_relay(process: subprocess.Popen[str]) -> None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)

        relay = start_relay()
        try:
            wait_for_relay(relay)

            def connect(authority: str) -> socket.socket:
                client = socket.create_connection(("127.0.0.1", relay_port), timeout=2)
                request = (
                    f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n"
                ).encode("ascii")
                client.sendall(request)
                return client

            with connect("github.com:443") as allowed:
                response = allowed.recv(4096)
                assert response.startswith(b"HTTP/1.1 200"), response
                allowed.sendall(b"relay-echo")
                assert allowed.recv(4096) == b"relay-echo"
            assert upstream_requests and upstream_requests[-1].startswith(
                b"CONNECT github.com:443 HTTP/1.1"
            )

            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as dns_client:
                dns_client.settimeout(2)
                allowed_query = dns_query("github.com", 0x1234)
                dns_client.sendto(allowed_query, ("127.0.0.1", dns_port))
                allowed_response, _ = dns_client.recvfrom(4096)
                assert struct.unpack("!H", allowed_response[2:4])[0] & 0x000F == 0
                assert dns_requests and dns_requests[-1] == allowed_query
                forwarded = len(dns_requests)
                forbidden_query = dns_query("example.com", 0x1235)
                dns_client.sendto(forbidden_query, ("127.0.0.1", dns_port))
                forbidden_response, _ = dns_client.recvfrom(4096)
                assert struct.unpack("!H", forbidden_response[2:4])[0] & 0x000F == 5
                assert len(dns_requests) == forwarded

            upstream_count = len(upstream_requests)
            for forbidden_authority in (
                "127.0.0.1:443",
                "github.com.evil.example:443",
                "github.com:80",
                "attacker-bucket.s3.amazonaws.com:443",
                "attacker.blob.core.windows.net:443",
            ):
                with connect(forbidden_authority) as denied:
                    response = denied.recv(4096)
                    assert response.startswith(b"HTTP/1.1 403"), (
                        forbidden_authority,
                        response,
                    )
            assert len(upstream_requests) == upstream_count
        finally:
            stop_relay(relay)
            rebound = start_relay()
            try:
                wait_for_relay(rebound)
            finally:
                stop_relay(rebound)
                upstream.shutdown()
                upstream_thread.join(timeout=3)
                dns_upstream.shutdown()
                dns_upstream_thread.join(timeout=3)

print("SIXLABJITLauncherGeneratorSmoke: PASS · exact render + filtered US relay + no install authority")
