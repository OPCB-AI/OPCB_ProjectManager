#!/usr/bin/env python3
import importlib.util
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
candidate_dir = project / "artifacts" / "jit-candidates" / "pr1198"
candidate_path = candidate_dir / manifest["output_name"]
candidate_manifest_path = candidate_dir / manifest["manifest_name"]
assert candidate_path.read_text(encoding="utf-8") == rendered
assert json.loads(candidate_manifest_path.read_text(encoding="utf-8")) == manifest
assert manifest["rendered_sha256"] == generator._digest(rendered.encode("utf-8"))
documentation = (project / "docs" / "sixlab-jit-shadow-controller.md").read_text(encoding="utf-8")
assert f"SHA-256 `{manifest['rendered_sha256']}`" in documentation
assert manifest["pull_number"] == PULL_NUMBER
assert manifest["expected_head"] == HEAD
assert manifest["attempt"] == 1
assert manifest["slot"] == SLOT
assert manifest["family"] == "spa-checks"
assert manifest["exact_label"] == f"sixlab-pr-job-{HEAD}-spa-checks"
assert manifest["prefix"] == "5589cr1"
assert manifest["launcher_prefix"] == "5589c-r1-usproxy5"
assert manifest["egress_profile"] == "us-proxy-v5"
assert manifest["supersedes_egress_profile"] == "us-proxy-v4"
assert manifest["upstream_proxy"] == "47.88.16.146:8443"
assert manifest["output_name"] == (
    "pr1198-one-job-launcher-5589c-r1-usproxy5-slot07-spa-checks.sh"
)
assert manifest["manifest_name"] == (
    "pr1198-one-job-launcher-5589c-r1-usproxy5-slot07-spa-checks.manifest.json"
)
assert manifest["capability_scope"] == "single-slot-single-family"
assert manifest["installation_authorized"] is False
assert manifest["token_mint_authorized"] is False
assert f"readonly PULL_NUMBER='{PULL_NUMBER}'" in rendered
assert f"readonly EXPECTED_HEAD='{HEAD}'" in rendered
assert "readonly ATTEMPT='1'" in rendered
assert "readonly PREFIX='5589cr1'" in rendered
assert "readonly LAUNCHER_PREFIX='5589c-r1-usproxy5'" in rendered
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
assert "systemd-run --user --scope --quiet --pipe" in rendered
assert rendered.count("IFS= read -r token") == 1
for forbidden_token_path in ("--stage-token", "--stage-existing-token", "token_path", "token_file", "registration-token", ".token"):
    assert forbidden_token_path not in rendered, forbidden_token_path
staging_attempt = subprocess.run(
    ["bash", str(candidate_path), "--stage-existing-token", SLOT],
    input="A" * 32 + "\n", capture_output=True, text=True,
)
assert staging_attempt.returncode != 0
assert "A" * 32 not in staging_attempt.stdout + staging_attempt.stderr
assert not (Path("/run") / f"sixlab-pr{PULL_NUMBER}-{manifest['prefix']}-ephemeral-{SLOT}.token").exists()
job_cleanup = rendered.split("  cleanup() {\n", 1)[1].split("\n  }\n", 1)[0]
assert "status=70" in job_cleanup
assert "(( status != 0 )) || status=70" not in job_cleanup
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


receipt_writer_source = rendered.split("<<'RECEIPT_PY'\n", 1)[1].split(
    "\nRECEIPT_PY", 1
)[0]
compile(receipt_writer_source, "exclusive-receipt-writer.py", "exec")
with tempfile.TemporaryDirectory(prefix="sixlab-receipt-writer.") as temporary:
    receipt_writer = Path(temporary) / "writer.py"
    receipt_writer.write_text(receipt_writer_source, encoding="utf-8")
    receipt_path = Path(temporary) / "job.receipt"
    arguments = [
        sys.executable,
        str(receipt_writer),
        str(receipt_path),
        "07",
        "sixlab-pr1198-5589cr1-07",
        HEAD,
        f"sixlab-pr-job-{HEAD}-spa-checks",
        "0",
        "2026-09-03T14:00:00+00:00",
    ]
    created = subprocess.run(arguments, check=False, capture_output=True, text=True)
    assert created.returncode == 0, created.stderr
    original_receipt = receipt_path.read_bytes()
    assert receipt_path.stat().st_mode & 0o777 == 0o444
    collision = subprocess.run(arguments, check=False, capture_output=True, text=True)
    assert collision.returncode != 0
    assert receipt_path.read_bytes() == original_receipt


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
