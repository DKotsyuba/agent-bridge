#!/usr/bin/env python3
"""Build and test the two standalone SDK crates using the workspace lock identities."""

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import tomllib


ROOT = Path(__file__).resolve().parents[1]


def literal(value):
    """Render manifest scalar, list or inline-table values without a TOML dependency."""
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, str):
        return json.dumps(value)
    if isinstance(value, list):
        return "[" + ", ".join(map(literal, value)) + "]"
    if isinstance(value, dict):
        return "{ " + ", ".join(f"{json.dumps(k)} = {literal(v)}" for k, v in value.items()) + " }"
    raise ValueError(f"Unsupported manifest value type: {type(value).__name__}")


def manifest(member, workspace):
    """Resolve only the supported member sections, preserving dependency features and lints."""
    if set(member) != {"package", "dependencies", "lints"}:
        raise ValueError("SDK manifest sections changed; review standalone packaging")
    package = {
        key: workspace["package"][key] if value == {"workspace": True} else value
        for key, value in member["package"].items()
    }
    dependencies = {
        key: workspace["dependencies"][key] if value == {"workspace": True} else value
        for key, value in member["dependencies"].items()
    }
    if "bridge-protocol" in dependencies:
        dependencies["bridge-protocol"] = {
            "version": "=" + workspace["package"]["version"],
            "path": "../bridge-protocol",
        }
    if member["lints"] != {"workspace": True}:
        raise ValueError("SDK lints changed; review standalone packaging")
    tables = {"package": package, "dependencies": dependencies}
    tables.update({"lints." + key: value for key, value in workspace["lints"].items()})
    return "\n\n".join(
        "[" + name + "]\n" + "\n".join(f"{json.dumps(k)} = {literal(v)}" for k, v in values.items())
        for name, values in tables.items()
    ) + "\n"


def external_identities(lock):
    """Return external package source/version/checksum identities for a lockfile."""
    return {
        (p["name"], p["version"], p["source"], p.get("checksum"))
        for p in tomllib.loads(lock.read_text())["package"]
        if "source" in p
    }


def main():
    """Create the requested archive after offline resolution and standalone contract tests."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    output = parser.parse_args().out.resolve()
    if output.exists():
        raise FileExistsError(output)
    temporary = Path(os.environ["TMPDIR"])
    if not temporary.is_absolute() or any(os.environ.get(k) != str(temporary) for k in ("TMP", "TEMP")):
        raise ValueError("Set TMPDIR, TMP and TEMP to one absolute owned directory")
    workspace = tomllib.loads((ROOT / "Cargo.toml").read_text())["workspace"]
    version = workspace["package"]["version"]
    identities = external_identities(ROOT / "Cargo.lock")
    environment = dict(os.environ)
    environment.setdefault("CARGO_TARGET_DIR", str(ROOT / "target"))
    with tempfile.TemporaryDirectory(prefix="sdk-", dir=temporary) as work:
        package = Path(work) / ("bridge-sdk-" + version)
        package.mkdir()
        for name in ("bridge-protocol", "bridge-sdk"):
            target = package / name
            shutil.copytree(ROOT / "crates" / name, target, ignore=shutil.ignore_patterns("target", ".git"))
            member = tomllib.loads((target / "Cargo.toml").read_text())
            (target / "Cargo.toml").write_text(manifest(member, workspace))
            shutil.copyfile(ROOT / "LICENSE", target / "LICENSE")
            shutil.copyfile(ROOT / "Cargo.lock", target / "Cargo.lock")
            command = ["cargo", "+1.98.1"]
            subprocess.run(command + ["metadata", "--offline", "--format-version", "1", "--manifest-path", str(target / "Cargo.toml")], env=environment, stdout=subprocess.DEVNULL, check=True)
            if not external_identities(target / "Cargo.lock") <= identities:
                raise ValueError("Standalone SDK changed external dependency identities")
            subprocess.run(command + ["test", "--offline", "--locked", "--manifest-path", str(target / "Cargo.toml")], env=environment, check=True)
        commit = subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True).strip()
        changed = subprocess.check_output(["git", "-C", str(ROOT), "diff", "--name-only", "HEAD"], text=True)
        (package / "SOURCE.json").write_text(json.dumps({"version": version, "commit": commit, "tracked_changes": bool(changed)}, indent=2) + "\n")
        (package / "README.md").write_text(
            "# Agent Bridge SDK source\n\n"
            "Both crates have standalone manifests and locked dependency identities.\n"
            "They are not published to crates.io. Test with:\n\n```sh\n"
            "cargo +1.98.1 test --offline --locked --manifest-path bridge-protocol/Cargo.toml\n"
            "cargo +1.98.1 test --offline --locked --manifest-path bridge-sdk/Cargo.toml\n```\n"
        )
        output.parent.mkdir(parents=True, exist_ok=True)
        with tarfile.open(output, "x:gz") as archive:
            archive.add(package, arcname=package.name)
    print(json.dumps({"archive": str(output), "version": version, "source": commit}))


if __name__ == "__main__":
    main()
