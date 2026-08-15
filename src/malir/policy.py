"""Behavior vocabulary and conservative API classification."""

from __future__ import annotations

from collections.abc import Iterable

OUTBOUND_REQUEST_CALLS = frozenset(
    {
        "requests.get",
        "requests.Session.get",
        "httpx.get",
        "httpx.Client.get",
        "aiohttp.ClientSession.get",
    }
)

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
                "os.startfile",
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
                "urllib.urlopen",
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


SENSITIVE_ENV_MARKERS = (
    "access_key",
    "api_key",
    "apikey",
    "cookie",
    "credential",
    "id_ed25519",
    "id_rsa",
    "passwd",
    "password",
    "private_key",
    "secret",
    "token",
    "wallet",
)


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

_DELETE_TEMP_NAMES = {"__pycache__", ".cache", "build", "cache", "dist", "temp", "tmp"}
_DELETE_TEMP_MARKERS = (
    "/__pycache__/",
    "/.cache/",
    "/build/",
    "/cache/",
    "/dist/",
    "/temp/",
    "/tmp/",
)
_DELETE_USER_DATA_MARKERS = (
    "/desktop/",
    "/documents/",
    "/downloads/",
    "/music/",
    "/pictures/",
    "/videos/",
    "credentials",
    "id_ed25519",
    "id_rsa",
    "user_documents",
    "wallet",
)
_DELETE_BROAD_TARGETS = {"*", "**", "/", ".", "..", "~"}
_PROCESS_SHELLS = {
    "bash",
    "cmd",
    "cmd.exe",
    "powershell",
    "powershell.exe",
    "pwsh",
    "sh",
    "wscript",
    "wscript.exe",
    "zsh",
}
_PROCESS_INTERPRETERS = {
    "node",
    "perl",
    "pypy",
    "pypy3",
    "python",
    "python.exe",
    "python3",
    "pythonw",
    "pythonw.exe",
    "ruby",
    "sys.executable",
}
_PROCESS_COMPILERS = {
    "c++",
    "cc",
    "clang",
    "clang++",
    "g++",
    "gcc",
    "go",
    "javac",
    "rustc",
}
_PROCESS_BUILD_TOOLS = {
    "cmake",
    "make",
    "meson",
    "ninja",
}
_PROCESS_PACKAGE_TOOLS = {
    "cargo",
    "npm",
    "pip",
    "pip3",
    "pnpm",
    "poetry",
    "uv",
    "yarn",
}


def process_target_class(value: str | None) -> str:
    if not value:
        return "generic"
    normalized = value.strip().lower().replace("\\", "/")
    if not normalized:
        return "generic"
    head = normalized.split(maxsplit=1)[0].strip("\"'")
    name = head.rsplit("/", 1)[-1]
    serialized_head = name.split("_", 1)[0]
    candidates = {name, serialized_head}
    if normalized == "sys.executable" or candidates & _PROCESS_INTERPRETERS:
        return "interpreter"
    if candidates & _PROCESS_SHELLS:
        return "shell"
    if candidates & _PROCESS_COMPILERS:
        return "compiler"
    if candidates & _PROCESS_BUILD_TOOLS:
        return "build_tool"
    if candidates & _PROCESS_PACKAGE_TOOLS:
        return "package_tool"
    return "generic"


def delete_target_class(value: str | None) -> str:
    if not value:
        return "generic"
    normalized = value.lower().replace("\\", "/").strip()
    basename = normalized.rstrip("/").rsplit("/", 1)[-1]
    if normalized in _DELETE_BROAD_TARGETS or "*" in normalized:
        return "broad"
    if (
        basename in _DELETE_TEMP_NAMES
        or basename.endswith((".pyc", ".tmp"))
        or basename.startswith(("cache.", "tmp."))
        or any(marker in normalized for marker in _DELETE_TEMP_MARKERS)
    ):
        return "temporary"
    if any(
        marker in f"/{normalized.strip('/')}/" for marker in _DELETE_USER_DATA_MARKERS
    ):
        return "user_data"
    return "generic"


def is_destructive_delete(value: str | None, *, recursive: bool = False) -> bool:
    target_class = delete_target_class(value)
    return target_class in {"broad", "user_data"} or (
        recursive and target_class != "temporary"
    )


def contains_marker(value: str | None, markers: Iterable[str]) -> bool:
    if not value:
        return False
    lowered = value.lower().replace("\\", "/")
    return any(marker in lowered for marker in markers)


def is_sensitive_env_name(value: str | None) -> bool:
    return contains_marker(value, SENSITIVE_ENV_MARKERS)


def is_sensitive_path(value: str | None) -> bool:
    return contains_marker(value, SENSITIVE_PATH_MARKERS)


def is_persistence_path(value: str | None) -> bool:
    if not value:
        return False
    normalized = value.lower().replace("\\", "/")
    if contains_marker(normalized, PERSISTENCE_PATH_MARKERS):
        return True
    return normalized.rsplit("/", 1)[-1].endswith(".pth")
