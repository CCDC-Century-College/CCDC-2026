import getpass
import shutil
import subprocess
import sys

# Internal Linux targets reachable from the Ubuntu workstation subnet
TARGETS = [
    {"name": "Rocky Ecom", "ip": "172.20.240.10", "user": "sysadmin"},
    {"name": "Ubuntu Email", "ip": "172.20.240.15", "user": "sysadmin"},
    {"name": "Debian Splunk", "ip": "172.20.240.20", "user": "sysadmin"}
]

# Verify sshpass exists before proceeding
if shutil.which("sshpass") is None:
    print("\n[!] ERROR: sshpass is not installed.")
    print("[!] Install it with:")
    print("    sudo apt install sshpass")
    sys.exit(1)

print("=== Internal Linux Credential Rotation ===\n")

OLD_LINUX_PASS = getpass.getpass(
    "[?] Enter current Linux password (Changeme1!): "
)

# Root password confirmation
while True:
    NEW_ROOT_PASS = getpass.getpass(
        "[?] Enter NEW root password: "
    )

    CONFIRM_ROOT_PASS = getpass.getpass(
        "[?] Confirm NEW root password: "
    )

    if NEW_ROOT_PASS == CONFIRM_ROOT_PASS:
        break

    print("\n[!] Root passwords do not match. Please try again.\n")

# Sysadmin password confirmation
while True:
    NEW_SYSADMIN_PASS = getpass.getpass(
        "[?] Enter NEW sysadmin password: "
    )

    CONFIRM_SYSADMIN_PASS = getpass.getpass(
        "[?] Confirm NEW sysadmin password: "
    )

    if NEW_SYSADMIN_PASS == CONFIRM_SYSADMIN_PASS:
        break

    print("\n[!] Sysadmin passwords do not match. Please try again.\n")

# Display target summary before making changes
print("\n=== Target Summary ===")

for target in TARGETS:
    print(
        f" - {target['name']} "
        f"({target['ip']}) "
        f"User: {target['user']}"
    )

input(
    "\nPress Enter to begin credential rotation "
    "or Ctrl+C to cancel..."
)

def execute_rotation(target):
    print(f"\n[*] Connecting to {target['name']} ({target['ip']})...")

    remote_script = (
        f'echo "{OLD_LINUX_PASS}" | sudo -S bash -c '
        f'\'echo "root:{NEW_ROOT_PASS}" | chpasswd && '
        f'echo "{target["user"]}:{NEW_SYSADMIN_PASS}" | chpasswd\''
    )

    cmd = [
        "sshpass",
        "-p",
        OLD_LINUX_PASS,
        "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        f'{target["user"]}@{target["ip"]}',
        remote_script
    ]

    try:
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=15
        )

    except subprocess.TimeoutExpired:
        return "TIMEOUT"


if __name__ == "__main__":

    print("\n=== Starting Credential Rotation ===")

    success_count = 0
    fail_count = 0

    for target in TARGETS:

        result = execute_rotation(target)

        if result == "TIMEOUT":
            print(
                f"[-] Failed on {target['name']}: Connection timed out"
            )
            fail_count += 1
            continue

        if result.returncode == 0:
            print(
                f"[+] Successfully updated {target['name']}"
            )
            success_count += 1

        else:
            error_msg = result.stderr.strip()

            if not error_msg:
                error_msg = "Unknown error"

            print(
                f"[-] Failed on {target['name']}: {error_msg}"
            )
            fail_count += 1

    print("\n=== Credential Rotation Complete ===")
    print(f"[+] Successful Hosts: {success_count}")
    print(f"[-] Failed Hosts: {fail_count}")