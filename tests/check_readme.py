"""Check documented commands without applying firewall rules."""

import argparse
import hashlib
import os
import re
import shlex
import subprocess
from pathlib import Path


def configuration_hashes():
    paths = [Path("/etc/default/ufw"), *Path("/etc/ufw").rglob("*")]
    return {
        str(path): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in paths
        if path.is_file()
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bash", default="bash")
    parser.add_argument(
        "--ufw",
        action="store_true",
        help="validate with installed UFW; run as root on a disposable runner",
    )
    args = parser.parse_args()
    readme = (
        Path(__file__)
        .resolve()
        .parents[1]
        .joinpath("README.md")
        .read_text(encoding="utf-8")
    )
    blocks = re.findall(r"```bash\n(.*?)```", readme, re.DOTALL)
    assert blocks, "No Bash examples found"
    for index, block in enumerate(blocks, 1):
        result = subprocess.run(
            [args.bash, "-n"],
            input=block,
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )
        assert result.returncode == 0, f"Bash block {index}: {result.stderr}"

    mutations = []
    for block in blocks:
        for line in block.splitlines():
            tokens = shlex.split(line, comments=True)
            if tokens[:2] != ["sudo", "ufw"]:
                continue
            command = [token for token in tokens[2:] if token != "--dry-run"]
            assert "reset" not in command, "Examples must preserve existing rules"
            if command[0] not in {"show", "status"}:
                mutations.append(command)
            if "allow" in command and command[0] != "delete":
                port = (
                    command[command.index("port") + 1]
                    if "port" in command
                    else next(
                        (
                            token.removesuffix("/tcp")
                            for token in command
                            if re.fullmatch(r"\d+/tcp", token)
                        ),
                        "",
                    )
                )
                if port in {
                    "587",
                    "628",
                    "629",
                    "110",
                    "5432",
                    "5666",
                    "$SSH_PORT",
                    "22",
                }:
                    assert "from" in command, f"Unrestricted optional service: {line}"
                    assert command[command.index("from") + 1] != "any", line
    ssh = next(
        index for index, command in enumerate(mutations) if "$ADMIN_SOURCE" in command
    )
    incoming = mutations.index(["default", "deny", "incoming"])
    enable = mutations.index(["enable"])
    assert ssh < incoming < enable, "SSH must be allowed before default-deny and enable"
    print(f"Bash syntax and rule-order checks passed: {len(blocks)} blocks")

    if not args.ufw:
        return
    assert os.geteuid() == 0, "UFW validation needs root on a disposable runner"
    before = configuration_hashes()
    count = 0
    for source in ("192.0.2.10/32", "2001:db8::10/128"):
        variables = {
            "$ADMIN_SOURCE": source,
            "$SMTP_SOURCE": source,
            "$CLIENT_SOURCE": source,
            "$SSH_PORT": "2222",
        }
        for command in mutations:
            resolved = [variables.get(token, token) for token in command]
            assert not any("$" in token for token in resolved), resolved
            # Every execution is a UFW dry run, including enable and delete.
            result = subprocess.run(
                ["ufw", "--dry-run", "--force", *resolved],
                text=True,
                capture_output=True,
                timeout=30,
                check=False,
                env={**os.environ, "LC_ALL": "C"},
            )
            assert result.returncode == 0, (
                f"{resolved}: {result.stdout}\n{result.stderr}"
            )
            count += 1
    assert before == configuration_hashes(), "Dry runs changed UFW configuration"
    print(f"Real UFW validation passed: {count} dry runs; configuration unchanged")


if __name__ == "__main__":
    main()
