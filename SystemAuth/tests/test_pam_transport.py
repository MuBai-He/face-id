#!/usr/bin/env python3
"""Root-only, isolated protocol tests. Never edits or loads the system PAM stack.

The fake PAM ABI exercises our C control flow, not macOS libpam semantics.
Only CI's separate macOS build uses real SDK headers and libpam.
"""
import ctypes
import os
import pathlib
import pwd
import select
import shutil
import socket
import struct
import sys
import subprocess
import tempfile
import threading
import time
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
HERE = pathlib.Path(__file__).resolve().parent
PAM_SUCCESS, PAM_AUTH_ERR, PAM_IGNORE, PAM_SILENT = 0, 7, 25, 0x8000
MAGIC, VERSION = 0x46494441, 1
DEFAULT = object()


class MockPAM(ctypes.Structure):
    _fields_ = [(name, ctypes.c_char_p) for name in ("service", "ruser", "user", "rhost")]


def read_request(conn):
    data = bytearray()
    while len(data) < 112:
        chunk = conn.recv(112 - len(data))
        if not chunk:
            raise AssertionError("unexpected request EOF")
        data.extend(chunk)
    return bytes(data)


@unittest.skipUnless(os.geteuid() == 0, "requires an isolated root-owned test socket")
class TransportTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="fid-test-", dir="/tmp")
        cls.socket_path = str(pathlib.Path(cls.temp.name) / "test.sock")
        cls.library = str(pathlib.Path(cls.temp.name) / "pam_test.so")
        cls.probe = str(pathlib.Path(cls.temp.name) / "probe")
        cc = shutil.which("cc") or "clang"
        common = [cc, "-std=c11", "-Wall", "-Wextra", "-Werror",
                  f'-DFID_AUTH_SOCKET="{cls.socket_path}"']
        subprocess.run(common + ["-shared", "-fPIC", "-I", str(HERE / "include"),
                                 str(ROOT / "PAM/pam_faceid.c"), str(HERE / "pam_shim.c"),
                                 "-o", cls.library], check=True)
        subprocess.run(common + [str(ROOT / "Daemon/faceid_authd_probe.c"),
                                 "-o", cls.probe], check=True)
        cls.dll = ctypes.CDLL(cls.library)
        cls.dll.pam_sm_authenticate.argtypes = [ctypes.POINTER(MockPAM), ctypes.c_int,
                                                ctypes.c_int, ctypes.c_void_p]
        cls.dll.pam_sm_authenticate.restype = ctypes.c_int
        # Prefer the account that invoked sudo. On some macOS installations,
        # the special "nobody" identity (UID -2) cannot be used as a normal
        # child process, and its interpreter may be inaccessible. The sudo
        # invoker is an ordinary non-root account and still exercises the
        # exact root-path / non-root-peer trust boundary.
        sudo_uid = os.environ.get("SUDO_UID")
        if sudo_uid is not None:
            account = pwd.getpwuid(int(sudo_uid))
        else:
            account = pwd.getpwnam("nobody")
        cls.name = account.pw_name
        cls.uid = account.pw_uid
        assert cls.uid != 0

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def tearDown(self):
        pathlib.Path(self.socket_path).unlink(missing_ok=True)

    def run_pam(self, service=b"sudo", user=DEFAULT, target=DEFAULT, rhost=None,
                flags=0, argc=0):
        user = self.name.encode() if user is DEFAULT else user
        target = self.name.encode() if target is DEFAULT else target
        pam = MockPAM(service, user, target, rhost)
        return self.dll.pam_sm_authenticate(ctypes.byref(pam), flags, argc, None)

    def with_server(self, result=1, *, bad_nonce=False, bad_version=False,
                    bad_magic=False, owner=None, permissions=0o600, truncate=False,
                    delay=0, fragment_delay=0, should_connect=True, pam_args=None,
                    fixed_nonce=None):
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(self.socket_path)
        os.chmod(self.socket_path, permissions)
        if owner is not None:
            os.chown(self.socket_path, owner, -1)
        server.listen(1)
        server.settimeout(5.5)
        errors, requests = [], []
        stop = threading.Event()

        def work():
            try:
                conn, _ = server.accept()
                with conn:
                    conn.settimeout(5.5)
                    req = read_request(conn)
                    requests.append(req)
                    magic, version, uid, pid = struct.unpack("!IIII", req[:16])
                    assert (magic, version, uid, pid) == (MAGIC, VERSION, self.uid & 0xffffffff, os.getpid())
                    assert req[32:96].split(b"\0", 1)[0] == self.name.encode()
                    assert req[96:] == b"sudo" + bytes(12)
                    nonce = fixed_nonce if fixed_nonce is not None else req[16:32]
                    if bad_nonce:
                        nonce = bytes([nonce[0] ^ 1]) + nonce[1:]
                    reply = struct.pack("!III", MAGIC + int(bad_magic),
                                        VERSION + int(bad_version), result) + nonce
                    if truncate:
                        reply = reply[:-1]
                    if stop.wait(delay):
                        return
                    if fragment_delay:
                        for byte in reply:
                            conn.sendall(bytes([byte]))
                            if stop.wait(fragment_delay):
                                return
                    else:
                        conn.sendall(reply)
            except (BrokenPipeError, ConnectionResetError) as exc:
                if not (delay or fragment_delay):
                    errors.append(repr(exc))
            except Exception as exc:
                errors.append(repr(exc))

        thread = threading.Thread(target=work, daemon=True)
        if should_connect:
            thread.start()
        try:
            start = time.monotonic()
            value = self.run_pam(**(pam_args or {}))
            self.last_duration = time.monotonic() - start
            if not should_connect:
                self.assertLess(self.last_duration, 1.0, "must reject before exchanging data")
                server.settimeout(0.02)
                with self.assertRaises(socket.timeout):
                    conn, _ = server.accept()
                    conn.close()
        finally:
            stop.set()
            if should_connect:
                thread.join(timeout=6)
            server.close()
            pathlib.Path(self.socket_path).unlink(missing_ok=True)
        if should_connect:
            self.assertFalse(thread.is_alive(), "server worker did not terminate")
        self.assertFalse(errors, f"server errors: {errors}")
        self.last_requests = requests
        return value

    def test_no_service_falls_back(self):
        self.assertEqual(self.run_pam(), PAM_IGNORE)

    def test_non_sudo_never_attempts_auth(self):
        for service in (b"su", b"login", b"sshd", b"screensaver", b"sudo-i", None):
            with self.subTest(service=service):
                self.assertEqual(self.with_server(should_connect=False,
                                 pam_args={"service": service}), PAM_IGNORE)

    def test_success_requires_explicit_approval(self):
        self.assertEqual(self.with_server(), PAM_SUCCESS)

    def test_known_rejection(self):
        self.assertEqual(self.with_server(0), PAM_AUTH_ERR)

    def test_unavailable_falls_back(self):
        self.assertEqual(self.with_server(2), PAM_IGNORE)

    def test_unknown_status_falls_back(self):
        self.assertEqual(self.with_server(99), PAM_IGNORE)

    def test_invalid_nonce_falls_back(self):
        self.assertEqual(self.with_server(bad_nonce=True), PAM_IGNORE)

    def test_invalid_version_falls_back(self):
        self.assertEqual(self.with_server(bad_version=True), PAM_IGNORE)

    def test_invalid_magic_falls_back(self):
        self.assertEqual(self.with_server(bad_magic=True), PAM_IGNORE)

    def test_untrusted_socket_is_not_used(self):
        self.assertEqual(self.with_server(owner=self.uid, should_connect=False), PAM_IGNORE)

    def test_socket_with_world_access_is_not_used(self):
        self.assertEqual(self.with_server(permissions=0o666, should_connect=False), PAM_IGNORE)

    def test_socket_with_group_access_is_not_used(self):
        self.assertEqual(self.with_server(permissions=0o660, should_connect=False), PAM_IGNORE)

    def test_truncated_response_falls_back(self):
        self.assertEqual(self.with_server(truncate=True), PAM_IGNORE)

    def test_unknown_requester_falls_back(self):
        self.assertEqual(self.with_server(should_connect=False,
                         pam_args={"user": b"__no_such_faceid_user__"}), PAM_IGNORE)

    def test_missing_or_empty_requester(self):
        for user in (None, b"", b"a" * 64):
            with self.subTest(user=user):
                self.assertEqual(self.with_server(should_connect=False,
                                 pam_args={"user": user}), PAM_IGNORE)

    def test_root_requester_is_not_supported(self):
        self.assertEqual(self.with_server(should_connect=False,
                         pam_args={"user": b"root", "target": b"root"}), PAM_IGNORE)

    def test_rootpw_cannot_use_invokers_face(self):
        self.assertEqual(self.with_server(should_connect=False,
                         pam_args={"target": b"root"}), PAM_IGNORE)

    def test_targetpw_cannot_use_invokers_face(self):
        self.assertNotEqual(pwd.getpwnam("daemon").pw_uid, self.uid)
        self.assertEqual(self.with_server(should_connect=False,
                         pam_args={"target": b"daemon"}), PAM_IGNORE)

    def test_missing_empty_or_unknown_pam_user(self):
        for target in (None, b"", b"__no_such_faceid_user__", b"a" * 64):
            with self.subTest(target=target):
                self.assertEqual(self.with_server(should_connect=False,
                                 pam_args={"target": target}), PAM_IGNORE)

    def test_remote_host_is_not_supported(self):
        self.assertEqual(self.with_server(should_connect=False,
                         pam_args={"rhost": b"remote.example.invalid"}), PAM_IGNORE)

    def test_silent_auth_never_starts_scan(self):
        self.assertEqual(self.with_server(should_connect=False,
                         pam_args={"flags": PAM_SILENT}), PAM_IGNORE)

    def test_unknown_module_options_fail_closed(self):
        self.assertEqual(self.with_server(should_connect=False,
                         pam_args={"argc": 1}), PAM_IGNORE)

    def test_null_handle_is_rejected(self):
        self.assertEqual(self.dll.pam_sm_authenticate(None, 0, 0, None), PAM_AUTH_ERR)

    def test_regular_file_is_not_a_service(self):
        pathlib.Path(self.socket_path).write_text("not a socket")
        self.assertEqual(self.run_pam(), PAM_IGNORE)

    def test_symlink_socket_is_not_used(self):
        other = self.socket_path + ".real"
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(other)
            os.chmod(other, 0o600)
            server.listen(1)
            os.symlink(other, self.socket_path)
            try:
                self.assertEqual(self.run_pam(), PAM_IGNORE)
            finally:
                os.unlink(other)

    def test_nonce_is_fresh_and_old_approval_cannot_be_replayed(self):
        self.assertEqual(self.with_server(), PAM_SUCCESS)
        first = self.last_requests[0][16:32]
        self.assertEqual(self.with_server(fixed_nonce=first), PAM_IGNORE)
        self.assertNotEqual(first, self.last_requests[0][16:32])

    def test_fragmented_valid_reply(self):
        self.assertEqual(self.with_server(fragment_delay=0.002), PAM_SUCCESS)

    def test_unresponsive_server_has_bounded_timeout(self):
        self.assertEqual(self.with_server(delay=5), PAM_IGNORE)
        self.assertGreater(self.last_duration, 3.5)
        self.assertLess(self.last_duration, 5.5)

    def test_trickle_reply_cannot_extend_deadline(self):
        self.assertEqual(self.with_server(fragment_delay=0.25), PAM_IGNORE)
        self.assertGreater(self.last_duration, 3.5)
        self.assertLess(self.last_duration, 5.5)

    def test_root_owned_path_does_not_make_nonroot_peer_trusted(self):
        # Spawn a new interpreter rather than forking a threaded ctypes host.
        script = """
import socket, struct, sys
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
    server.bind(sys.argv[1])
    server.listen(1)
    server.settimeout(5)
    print("R", flush=True)
    conn, _ = server.accept()
    with conn:
        conn.settimeout(5)
        data = conn.recv(112)
        if data:
            conn.sendall(struct.pack("!III", 0x46494441, 1, 1) + data[16:32])
"""
        os.chown(self.temp.name, self.uid, -1)
        child = None
        try:
            child = subprocess.Popen([sys.executable, "-c", script, self.socket_path],
                                     user=self.uid, group=pwd.getpwnam(self.name).pw_gid,
                                     extra_groups=[], stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE)
            self.assertTrue(select.select([child.stdout], [], [], 5)[0])
            self.assertEqual(child.stdout.read(1), b"R")
            os.chown(self.socket_path, 0, 0)
            os.chmod(self.socket_path, 0o600)
            os.chown(self.temp.name, 0, 0)
            self.assertEqual(self.run_pam(), PAM_IGNORE)
            _, errors = child.communicate(timeout=6)
            self.assertEqual(child.returncode, 0, errors.decode())
        finally:
            os.chown(self.temp.name, 0, 0)
            if child is not None:
                if child.poll() is None:
                    child.kill()
                child.communicate()

    def start_probe(self):
        process = subprocess.Popen([self.probe], stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL)

        def cleanup():
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=6)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                self.fail("probe failed to stop")

        self.addCleanup(cleanup)
        deadline = time.monotonic() + 3
        while not pathlib.Path(self.socket_path).exists():
            if process.poll() is not None or time.monotonic() >= deadline:
                self.fail("probe did not start")
            time.sleep(0.01)
        return process

    def test_probe_never_approves(self):
        self.start_probe()
        self.assertEqual(self.run_pam(), PAM_IGNORE)

    def test_probe_preserves_preexisting_path(self):
        path = pathlib.Path(self.socket_path)
        path.write_text("keep me")
        result = subprocess.run([self.probe], capture_output=True, timeout=3)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(path.read_text(), "keep me")

    def test_probe_rejects_invalid_header(self):
        self.start_probe()
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(5)
            conn.connect(self.socket_path)
            conn.sendall(bytes(112))
            self.assertEqual(conn.recv(28), b"")


if __name__ == "__main__":
    if os.geteuid() != 0:
        raise SystemExit("Run only in an isolated test VM/container as root; no system PAM files are changed.")
    unittest.main(verbosity=2)
