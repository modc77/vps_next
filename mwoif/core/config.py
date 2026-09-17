from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from .redact import redact_mapping

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _load_env_file(path: Path) -> None:
    if not path.exists():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


@dataclass(frozen=True)
class DatabaseConfig:
    host: str
    port: int
    user: str
    password: str
    database: str
    charset: str = "utf8mb4"
    connect_timeout: int = 5
    read_timeout: int = 15
    write_timeout: int = 15

    def redacted(self) -> dict[str, object]:
        return redact_mapping(
            {
                "host": self.host,
                "port": self.port,
                "user": self.user,
                "password": self.password,
                "database": self.database,
                "charset": self.charset,
                "connect_timeout": self.connect_timeout,
                "read_timeout": self.read_timeout,
                "write_timeout": self.write_timeout,
            }
        )


@dataclass(frozen=True)
class VaultConfig:
    master_key_b64: str | None
    key_version: int = 1

    @property
    def configured(self) -> bool:
        return bool(self.master_key_b64)

    def redacted(self) -> dict[str, object]:
        return redact_mapping(
            {
                "master_key_b64": self.master_key_b64,
                "key_version": self.key_version,
                "configured": self.configured,
            }
        )


@dataclass(frozen=True)
class AppConfig:
    env: str
    log_level: str
    database: DatabaseConfig
    vault: VaultConfig
    extra: dict[str, str]
    project_root: Path = PROJECT_ROOT

    def redacted(self) -> dict[str, object]:
        return {
            "env": self.env,
            "log_level": self.log_level,
            "project_root": str(self.project_root),
            "database": self.database.redacted(),
            "vault": self.vault.redacted(),
            "devplay": redact_mapping({k: v for k, v in self.extra.items() if k.startswith("MWOIF_DEVPLAY_") or k.startswith("MWOIF_GAME_")}),
        }


def _int_from_env(name: str, default: int) -> int:
    raw = os.environ.get(name, str(default))
    try:
        return int(raw)
    except ValueError as exc:
        raise ValueError(f"Invalid {name}: {raw!r}") from exc


def load_config(env_file: str | Path | None = None) -> AppConfig:
    env_path = Path(env_file) if env_file else PROJECT_ROOT / ".env"
    _load_env_file(env_path)

    database = DatabaseConfig(
        host=os.environ.get("MWOIF_DB_HOST", "127.0.0.1"),
        port=_int_from_env("MWOIF_DB_PORT", 3306),
        user=os.environ.get("MWOIF_DB_USER", "root"),
        password=os.environ.get("MWOIF_DB_PASSWORD", ""),
        database=os.environ.get("MWOIF_DB_NAME", "m_woif"),
        charset=os.environ.get("MWOIF_DB_CHARSET", "utf8mb4"),
        connect_timeout=_int_from_env("MWOIF_DB_CONNECT_TIMEOUT", 5),
        read_timeout=_int_from_env("MWOIF_DB_READ_TIMEOUT", 15),
        write_timeout=_int_from_env("MWOIF_DB_WRITE_TIMEOUT", 15),
    )
    vault = VaultConfig(
        master_key_b64=os.environ.get("MWOIF_HEART_MASTER_KEY_B64") or None,
        key_version=_int_from_env("MWOIF_HEART_KEY_VERSION", 1),
    )
    return AppConfig(
        env=os.environ.get("MWOIF_ENV", "local"),
        log_level=os.environ.get("MWOIF_LOG_LEVEL", "INFO"),
        database=database,
        vault=vault,
        extra={k: v for k, v in os.environ.items() if k.startswith("MWOIF_")},
    )
