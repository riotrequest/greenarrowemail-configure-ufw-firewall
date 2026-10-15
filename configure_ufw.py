#!/usr/bin/env python3
"""Interactive UFW setup for a standard Ubuntu/Debian GreenArrow host."""

import argparse
import ipaddress
import os
import shlex
import shutil
import subprocess
import sys
import tempfile


def run(*command):
    print("+ " + shlex.join(command), flush=True)
    subprocess.run(command, check=True)


def build_rules(port, sources, smtp=False, web=False, outgoing=False):
    if not port.isascii() or not port.isdecimal() or not 1 <= int(port) <= 65535:
        raise ValueError("SSH port must be a number from 1 to 65535")
    port = str(int(port))
    networks = [
        ipaddress.ip_network(source.strip(), strict=False)
        for source in sources.split(",")
    ]
    if any(network.prefixlen == 0 for network in networks):
        raise ValueError("Administrator sources must not include the entire Internet")
    public = ([25] if smtp else []) + ([80, 443] if web else [])
    if int(port) in public:
        raise ValueError("SSH shares a selected public port; use the manual guide")
    commands = [
        [
            "prepend",
            "allow",
            "in",
            "proto",
            "tcp",
            "from",
            str(network),
            "to",
            "any",
            "port",
            port,
            "comment",
            "SSH administration",
        ]
        for network in networks
    ]
    commands += [["allow", "in", f"{value}/tcp"] for value in public]
    if outgoing:
        commands.append(["default", "allow", "outgoing"])
    commands.append(["default", "deny", "incoming"])
    return commands


def yes(question):
    answer = input(question + " [y/N]: ").strip().lower()
    if answer not in {"", "n", "no", "y", "yes"}:
        raise ValueError("Answer y or n")
    return answer in {"y", "yes"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="preview only; no installation, backup, or enable",
    )
    args = parser.parse_args()
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        raise ValueError("Run with sudo python3 on the target Ubuntu/Debian host")
    if not sys.stdin.isatty():
        raise ValueError(
            "An interactive terminal is required; download first, then run"
        )
    if not shutil.which("apt-get"):
        raise ValueError("This setup supports Ubuntu/Debian hosts with apt-get")

    print(
        "Keep SSH open and have your provider console ready. Check the cloud firewall too."
    )
    print(
        "Existing rules are preserved, including public openings. Active UFW changes immediately."
    )
    print(
        "Cover ALL required incoming services before applying; use the manual guide for custom hosts."
    )
    if shutil.which("ss"):
        run("ss", "-lnt")
    port = input("Actual SSH listening port (no default): ").strip()
    sources = input(
        "Trusted administrator IPs/CIDRs, comma-separated (IPv4 and/or IPv6): "
    ).strip()
    commands = build_rules(
        port,
        sources,
        smtp=yes("Allow public incoming SMTP/bounces on TCP 25?"),
        web=yes("Allow public HTTP/HTTPS on TCP 80 and 443?"),
        outgoing=yes(
            "Allow all outgoing traffic? No preserves the current outgoing policy"
        ),
    )
    ufw = shutil.which("ufw")
    if ufw:
        run("ufw", "status", "verbose")
        run("ufw", "show", "added")
    print("\nProposed rules (plus ufw enable after applying):")
    for command in commands:
        print("  " + shlex.join(["ufw", *command]))
    print(
        "Optional injection, database, monitoring, vendor access and Fail2Ban: see README."
    )
    if (
        not args.dry_run
        and input("Type APPLY to back up and apply this plan: ").strip() != "APPLY"
    ):
        print("Cancelled; no changes made.")
        return
    if not ufw:
        if args.dry_run:
            raise ValueError(
                "Plan shown; install UFW first to validate with native dry runs"
            )
        run("apt-get", "update")
        run("apt-get", "install", "--yes", "ufw")

    # Validate every rule before applying any. Never dry-run enable: it can
    # still save ENABLED=yes in ufw.conf on supported distribution packages.
    for command in commands:
        run("ufw", "--dry-run", *command)
    if args.dry_run:
        print("Preview complete; no rules, policies or enable flag changed.")
        return

    descriptor, backup = tempfile.mkstemp(
        prefix="ufw-before-", suffix=".tar.gz", dir="/root"
    )
    os.close(descriptor)
    run("tar", "-C", "/etc", "-czf", backup, "ufw", "default/ufw")
    print("Configuration backup: " + backup)
    for command in commands:
        run("ufw", *command)
    run("ufw", "enable")  # Keep UFW's own confirmation; never --force.
    run("ufw", "status", "verbose")
    print("Open a NEW SSH connection from an allowed source before closing this one.")
    print("Verify mail/web access and remove obsolete broad rules using the README.")


if __name__ == "__main__":
    try:
        main()
    except (
        ValueError,
        OSError,
        subprocess.CalledProcessError,
        EOFError,
        KeyboardInterrupt,
    ) as error:
        print(
            f"Stopped: {error}. If application began, inspect UFW via your open session/console.",
            file=sys.stderr,
        )
        sys.exit(1)
