"""
Fleet Configuration Engine & YAML Parser/Generator.
Provides configuration loading, saving, generation, and migration from existing configs.
"""

import os
import json
import re
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field, asdict


@dataclass
class NodeCapability:
    os: str = "linux"
    arch: str = "x86_64"
    gpus: int = 0
    browsers: List[str] = field(default_factory=lambda: ["chrome", "firefox"])
    custom: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FleetConfig:
    cluster_name: str = "harness-fleet-primary"
    conductor_host: str = "127.0.0.1"
    conductor_port: int = 9443
    discovery_mode: str = "static"  # static, mdns, k8s, ssh
    heartbeat_interval: float = 5.0
    max_missed_heartbeats: int = 3
    token_ttl: int = 3600
    quarantine_threshold: int = 5
    quarantine_window_seconds: int = 60
    static_workers: List[str] = field(default_factory=lambda: ["127.0.0.1:9444"])
    default_shards: str = "auto"
    timeout_seconds: int = 300
    retry_infra_failures: bool = True
    max_infra_retries: int = 3
    retry_strategy: str = "immediate"
    base_delay_ms: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FleetConfig":
        valid_fields = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in valid_fields}
        return cls(**filtered)

    def to_yaml(self) -> str:
        """Serializes FleetConfig instance into YAML formatted string."""
        lines = ["# Fleet Configuration", ""]
        for k, v in self.to_dict().items():
            if isinstance(v, list):
                lines.append(f"{k}:")
                for item in v:
                    lines.append(f"  - {item}")
            else:
                lines.append(f"{k}: {v}")
        return "\n".join(lines) + "\n"

    @classmethod
    def from_yaml(cls, yaml_str: str) -> "FleetConfig":
        """Parses FleetConfig instance from a YAML formatted string."""
        if not yaml_str:
            return cls()
        data: Dict[str, Any] = {}
        current_list_key: Optional[str] = None

        for line in yaml_str.splitlines():
            line_str = line.strip()
            if not line_str or line_str.startswith("#"):
                continue
            if line_str.startswith("- ") and current_list_key:
                val = line_str[2:].strip().strip('"').strip("'")
                data[current_list_key].append(val)
                continue
            if ":" in line_str:
                key, val = line_str.split(":", 1)
                key = key.strip()
                val = val.strip().strip('"').strip("'")
                if not val:
                    data[key] = []
                    current_list_key = key
                else:
                    current_list_key = None
                    if val.isdigit():
                        data[key] = int(val)
                    elif val.replace(".", "", 1).isdigit() and "." in val:
                        data[key] = float(val)
                    elif val.lower() == "true":
                        data[key] = True
                    elif val.lower() == "false":
                        data[key] = False
                    else:
                        data[key] = val
        return cls.from_dict(data)


@dataclass
class TaskConfig:
    """
    Configuration specification for OpenHarness tasks.
    Supports configurable retry strategies and base backoff delays with backward compatibility.
    """
    task_id: str = ""
    name: str = ""
    retry_strategy: str = "immediate"
    base_delay_ms: int = 0
    max_retries: int = 3
    timeout_seconds: int = 3600
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Converts TaskConfig to a dictionary representation."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TaskConfig":
        """
        Parses TaskConfig from a dictionary with backward compatibility for missing retry fields.

        :param data: Dictionary containing task configuration key-value pairs.
        :return: Parsed TaskConfig instance with default fallbacks for missing fields.
        """
        if not isinstance(data, dict):
            return cls()
        valid_fields = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in valid_fields}
        return cls(**filtered)

    def to_yaml(self) -> str:
        """Simple YAML serializer for TaskConfig structures."""
        lines = ["# Task Configuration", ""]
        for k, v in self.to_dict().items():
            if isinstance(v, dict):
                lines.append(f"{k}:")
                for dk, dv in v.items():
                    lines.append(f"  {dk}: {dv}")
            else:
                lines.append(f"{k}: {v}")
        return "\n".join(lines) + "\n"

    @classmethod
    def from_yaml(cls, yaml_str: str) -> "TaskConfig":
        """
        Parses TaskConfig from a YAML string with default retry fallbacks.

        :param yaml_str: String containing YAML task configuration data.
        :return: Parsed TaskConfig object.
        """
        if not yaml_str:
            return cls()
        data: Dict[str, Any] = {}
        for line in yaml_str.splitlines():
            line_str = line.strip()
            if not line_str or line_str.startswith("#"):
                continue
            if ":" in line_str:
                key, val = line_str.split(":", 1)
                key = key.strip()
                val = val.strip().strip('"').strip("'")
                if val.isdigit():
                    data[key] = int(val)
                elif val.replace(".", "", 1).isdigit() and "." in val:
                    data[key] = float(val)
                elif val.lower() == "true":
                    data[key] = True
                elif val.lower() == "false":
                    data[key] = False
                else:
                    data[key] = val
        return cls.from_dict(data)


def generate_default_config(cluster_name: str = "harness-fleet-primary") -> FleetConfig:
    return FleetConfig(cluster_name=cluster_name)


def save_config(config: FleetConfig, path: str = "fleet.yaml") -> str:
    content = config.to_yaml()
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return os.path.abspath(path)


def load_config(path: str = "fleet.yaml") -> FleetConfig:
    if not os.path.exists(path):
        return FleetConfig()
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
    if content.strip().startswith("{"):
        return FleetConfig.from_dict(json.loads(content))
    return FleetConfig.from_yaml(content)


def migrate_config(existing_path: Optional[str] = None) -> FleetConfig:
    """
    Detects existing project configurations (pyproject.toml, pytest.ini, openharness.json)
    and produces a migrated FleetConfig.
    """
    config = FleetConfig()

    candidates = [existing_path] if existing_path else [
        "openharness.json",
        "pyproject.toml",
        "pytest.ini",
        ".openharness.json"
    ]

    for cand in candidates:
        if not cand or not os.path.exists(cand):
            continue
        try:
            with open(cand, "r", encoding="utf-8") as f:
                content = f.read()

            if cand.endswith(".json"):
                data = json.loads(content)
                if "fleet" in data:
                    return FleetConfig.from_dict(data["fleet"])
                if "cluster_name" in data:
                    return FleetConfig.from_dict(data)

            elif cand.endswith(".toml"):
                # Simple extraction of openharness or fleet settings
                if "[tool.harness]" in content or "[tool.openharness]" in content:
                    config.cluster_name = "migrated-toml-fleet"
                if "shards" in content:
                    m = re.search(r'shards\s*=\s*"?(\w+)"?', content)
                    if m:
                        config.default_shards = m.group(1)

            elif cand.endswith(".ini"):
                if "fleet" in content or "pytest" in content:
                    config.cluster_name = "migrated-ini-fleet"
        except Exception:
            pass

    return config
