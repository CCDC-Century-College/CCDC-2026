#!/usr/bin/env python3
import getpass
import os
import shutil
import subprocess
import sys

LOCAL_ADMIN = "sysadmin"

# Remote targets processed in order. A failure is reported and the loop continues.
TARGETS = [
    {"name": "Kali Workstation", "ip": "172.17.0.2", "user": "sysadmin"},
    {"name": "Rocky E-commerce", "ip": "172.20.240.10", "user": "sysadmin"},
    {"name": "Ubuntu Email", "ip": "172.20.240.15", "user": "sysadmin"},
    {"name": "Debian Splunk OS", "ip": "172.20.240.20", "user": "sysadmin"},
]


def prompt_confirmed_password(label):
    while True:
        password = getpass.getpass(f"[?] Enter NEW {label} password: ")
        confirmation = getpass.getpass(f"[?] Confirm NEW {label} password: ")

        if not password:
            print("[!] Password cannot be empty. Try again.\n")
        elif password != confirmation:
            print("[!] Passwords do not match. Try again.\n")
        else:
            return password


def rotate_local(current_password, new_root_password, new_sysadmin_password):
    # sudo -k forces sudo to read the current password from the first stdin line.
    # chpasswd then reads the two credential-change lines that follow it.
    password_input = (
        f"{current_password}\n"
        f"root:{new_root_password}\n"
        f"{LOCAL_ADMIN}:{new_sysadmin_password}\n"
    )

    try:
        return subprocess.run(
            ["sudo", "-k", "-S", "-p", "", "chpasswd"],
            input=password_input,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return "TIMEOUT"


def rotate_remote(target, current_password, new_root_password, new_sysadmin_password):
    # sshpass -e reads the SSH password from the temporary SSHPASS environment
    # variable instead of placing it in the command-line arguments.
    env = os.environ.copy()
    env["SSHPASS"] = current_password

    # Passwords are sent through stdin. No password file is created.
    password_input = (
        f"{current_password}\n"
        f"root:{new_root_password}\n"
        f"{target['user']}:{new_sysadmin_password}\n"
    )

    command = [
        "sshpass",
        "-e",
        "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "LogLevel=ERROR",
        "-o", "ConnectTimeout=10",
        f"{target['user']}@{target['ip']}",
        "sudo", "-k", "-S", "-p", "", "chpasswd",
    ]

    try:
        return subprocess.run(
            command,
            input=password_input,
            capture_output=True,
            text=True,
            timeout=20,
            env=env,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return "TIMEOUT"


def report_result(name, result):
    if result == "TIMEOUT":
        print(f"[-] Failed on {name}: connection timed out")
        return False

    if result.returncode == 0:
        print(f"[+] Successfully updated {name}")
        return True

    error_message = result.stderr.strip() or "Unknown error"
    print(f"[-] Failed on {name}: {error_message}")
    return False


def main():
    if shutil.which("sshpass") is None:
        print("[!] ERROR: sshpass is not installed.")
        print("[!] Install it with: sudo apt install sshpass")
        sys.exit(1)

    print("=== Linux Credential Rotation ===\n")

    current_password = getpass.getpass(
        "[?] Enter CURRENT sysadmin password: "
    )
    new_root_password = prompt_confirmed_password("root")
    new_sysadmin_password = prompt_confirmed_password("sysadmin")

    print("\n=== Target Summary ===")
    print(f" - Ubuntu Workstation (local) User: {LOCAL_ADMIN}")
    for target in TARGETS:
        print(
            f" - {target['name']} ({target['ip']}) "
            f"User: {target['user']}"
        )

    input("\nPress Enter to begin credential rotation or Ctrl+C to cancel...")

    success_count = 0
    fail_count = 0

    print("\n=== Starting Credential Rotation ===")
    print("\n[*] Updating Ubuntu Workstation locally...")
    local_result = rotate_local(
        current_password,
        new_root_password,
        new_sysadmin_password,
    )

    if report_result("Ubuntu Workstation", local_result):
        success_count += 1
    else:
        fail_count += 1

    for target in TARGETS:
        print(f"\n[*] Connecting to {target['name']} ({target['ip']})...")
        result = rotate_remote(
            target,
            current_password,
            new_root_password,
            new_sysadmin_password,
        )

        if report_result(target["name"], result):
            success_count += 1
        else:
            fail_count += 1
            # Continue to the next target after any failure.
            continue

    print("\n=== Credential Rotation Complete ===")
    print(f"[+] Successful Hosts: {success_count}")
    print(f"[-] Failed Hosts: {fail_count}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Credential rotation cancelled.")
        sys.exit(130)
