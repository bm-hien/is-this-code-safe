"""Behavior vocabulary and conservative API classification."""

from __future__ import annotations

from collections.abc import Iterable

CALL_GROUPS: tuple[tuple[frozenset[str], str, str, str], ...] = (
    (
        frozenset(
            {
                "eval",
                "builtins.eval",
                "exec",
                "builtins.exec",
            }
        ),
        "DYNAMIC_EXEC",
        "sink",
        "dynamic code execution",
    ),
    (
        frozenset({"compile", "builtins.compile"}),
        "CODE_COMPILE",
        "transform",
        "runtime source compilation",
    ),
    (
        frozenset(
            {
                "__import__",
                "builtins.__import__",
                "importlib.import_module",
            }
        ),
        "DYNAMIC_IMPORT",
        "transform",
        "dynamic module loading",
    ),
    (
        frozenset(
            {
                "subprocess.run",
                "subprocess.call",
                "subprocess.check_call",
                "subprocess.check_output",
                "subprocess.Popen",
                "os.system",
                "os.popen",
                "commands.getoutput",
            }
        ),
        "PROCESS_EXEC",
        "sink",
        "process or shell execution",
    ),
    (
        frozenset(
            {
                "requests.post",
                "requests.put",
                "requests.patch",
                "requests.Session.post",
                "requests.Session.put",
                "httpx.post",
                "httpx.put",
                "httpx.Client.post",
                "httpx.Client.put",
                "aiohttp.ClientSession.post",
                "urllib.request.urlopen",
                "socket.socket.send",
                "socket.socket.sendall",
            }
        ),
        "NETWORK_SEND",
        "sink",
        "outbound data transfer",
    ),
    (
        frozenset(
            {
                "requests.get",
                "requests.Session.get",
                "httpx.get",
                "httpx.Client.get",
                "aiohttp.ClientSession.get",
                "urllib.request.urlretrieve",
                "socket.create_connection",
                "socket.socket.connect",
            }
        ),
        "NETWORK_RECEIVE",
        "source",
        "remote communication",
    ),
    (
        frozenset(
            {
                "os.getenv",
                "os.environ.get",
            }
        ),
        "ENV_READ",
        "source",
        "environment variable access",
    ),
    (
        frozenset(
            {
                "base64.b64decode",
                "base64.urlsafe_b64decode",
                "binascii.unhexlify",
                "codecs.decode",
                "zlib.decompress",
                "gzip.decompress",
                "bz2.decompress",
                "lzma.decompress",
            }
        ),
        "DECODE",
        "transform",
        "encoded or compressed data decoding",
    ),
    (
        frozenset(
            {
                "base64.b64encode",
                "base64.urlsafe_b64encode",
                "binascii.hexlify",
                "zlib.compress",
                "gzip.compress",
            }
        ),
        "ENCODE",
        "transform",
        "data encoding or compression",
    ),
    (
        frozenset(
            {
                "pickle.loads",
                "marshal.loads",
                "yaml.load",
                "dill.loads",
                "cloudpickle.loads",
            }
        ),
        "UNSAFE_DESERIALIZE",
        "sink",
        "potentially unsafe deserialization",
    ),
    (
        frozenset(
            {
                "os.remove",
                "os.unlink",
                "os.rmdir",
                "shutil.rmtree",
                "pathlib.Path.unlink",
                "pathlib.Path.rmdir",
            }
        ),
        "FILE_DELETE",
        "sink",
        "file or directory deletion",
    ),
    (
        frozenset(
            {
                "platform.platform",
                "platform.uname",
                "platform.node",
                "socket.gethostname",
                "getpass.getuser",
                "os.getuid",
            }
        ),
        "SYSTEM_DISCOVERY",
        "source",
        "host or user discovery",
    ),
)


PROCESS_PREFIXES = (
    "os.spawn",
    "os.exec",
    "subprocess.",
)
READ_METHODS = {".read_text", ".read_bytes"}
WRITE_METHODS = {".write_text", ".write_bytes"}


def classify_call(name: str) -> tuple[str, str, str] | None:
    for names, op, category, detail in CALL_GROUPS:
        if name in names:
            return op, category, detail
    if name.startswith(PROCESS_PREFIXES):
        return "PROCESS_EXEC", "sink", "process or shell execution"
    if any(name.endswith(item) for item in READ_METHODS):
        return "FILE_READ", "source", "file read"
    if any(name.endswith(item) for item in WRITE_METHODS):
        return "FILE_WRITE", "sink", "file write"
    return None


SENSITIVE_PATH_MARKERS = (
    ".ssh",
    "id_rsa",
    "id_ed25519",
    ".aws",
    "credentials",
    ".config/gcloud",
    ".azure",
    ".npmrc",
    ".pypirc",
    ".netrc",
    "wallet",
    "cookies",
    "login data",
    "history",
    "/etc/passwd",
    "/etc/shadow",
)

PERSISTENCE_PATH_MARKERS = (
    ".bashrc",
    ".zshrc",
    ".profile",
    "crontab",
    "/cron.",
    "systemd",
    "startup",
    "launchagents",
    "launchdaemons",
    "sitecustomize.py",
)


def contains_marker(value: str | None, markers: Iterable[str]) -> bool:
    if not value:
        return False
    lowered = value.lower().replace("\\", "/")
    return any(marker in lowered for marker in markers)


def is_sensitive_path(value: str | None) -> bool:
    return contains_marker(value, SENSITIVE_PATH_MARKERS)


def is_persistence_path(value: str | None) -> bool:
    if not value:
        return False
    normalized = value.lower().replace("\\", "/")
    if contains_marker(normalized, PERSISTENCE_PATH_MARKERS):
        return True
    return normalized.rsplit("/", 1)[-1].endswith(".pth")
