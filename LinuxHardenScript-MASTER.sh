#!/usr/bin/env bash
# ==============================================================================
# CCDC LINUX HARDENING MASTER TEMPLATE
# ==============================================================================
# Purpose:
#   Create ONE host-specific working copy per Linux server, fill the tournament
#   placeholders from the topology map and verified live state, run preflight,
#   then use apply mode only after review and approval.
#
# Safety model:
#   - The master template defaults to preflight and makes no changes.
#   - Required placeholders fail closed.
#   - No reusable plaintext password is stored.
#   - UFW is never reset automatically in preserve mode.
#   - Rebuild mode requires separate approval and console confirmation.
#   - Unknown services are never disabled automatically.
#   - Backups and logs remain local on the competition VM.
#
# Usage:
#   1. cp LinuxHardenScript-MASTER.sh LinuxHardenScript-HOST-WORKING.sh
#   2. Edit only the working copy.
#   3. sudo bash LinuxHardenScript-HOST-WORKING.sh preflight
#   4. Review the printed plan and local log.
#   5. Set approval values only after review.
#   6. sudo bash LinuxHardenScript-HOST-WORKING.sh apply
#
# IMPORTANT:
#   Follow current competition rules, NISE/Team Portal notices, injects, and the
#   Current Event Card. Do not guess values merely to pass validation.
# ==============================================================================

set -uo pipefail
IFS=$'\n\t'
umask 077

SCRIPT_VERSION="1.0"
MODE="${1:-preflight}"              # preflight | apply

# ==============================================================================
# TOURNAMENT AND LINUX HOST PROFILE
# Keep placeholders in the master. Fill them only in a host working copy.
# ==============================================================================
TEAM_NUMBER="[PUT_TEAM_NUMBER_HERE]"
TARGET_HOSTNAME="[PUT_LINUX_HOSTNAME_HERE]"
TARGET_SERVER_ROLE="[PUT_ecommerce_email_OR_splunk_HERE]"
TARGET_PRIVATE_IP="[PUT_PRIVATE_IP_HERE]"

# Informational when implemented through upstream NAT. This address is not
# required to exist on a local Linux interface.
TARGET_PUBLIC_IP="[PUT_PUBLIC_OR_NAT_IP_HERE]"

# none     = inspect and report only; do not modify the host firewall
# preserve = back up current UFW state and add only verified missing permits
# rebuild  = back up UFW, reset it, and construct an approved replacement policy
FIREWALL_MODE="none"

# Set to true only in the host working copy after the profile has been reviewed.
HOST_PROFILE_APPROVED="false"
FIREWALL_PROFILE_APPROVED="false"
FIREWALL_REBUILD_APPROVED="false"
CONSOLE_RECOVERY_CONFIRMED="false"
ROLLBACK_REVIEWED="false"

# If SSH is required for administration, enter its verified TCP port here.
# Leave blank only if SSH is not required or is handled outside this script.
VERIFIED_ADMIN_SSH_PORT="[PUT_VERIFIED_SSH_PORT_OR_NONE_HERE]"

# Optional verified source ranges for administrative access only.
# Leave empty unless the current event has provided and verified the ranges.
VERIFIED_ADMIN_SOURCE_RANGES=(
)

# Host-specific required service ports. Examples belong in comments only.
VERIFIED_REQUIRED_TCP_PORTS=(
    # E-commerce candidates after verification: 80 443
    # Email candidates after verification: 25 465 587 110 995 143 993 80 443
    # Splunk management identified in supplied event material: 8089
)

VERIFIED_REQUIRED_UDP_PORTS=(
    # Add only event-verified UDP ports for this Linux host.
)

# Format each range as start:end, for example an explicitly configured FTP
# passive range. Never guess a range.
VERIFIED_REQUIRED_TCP_RANGES=(
)

# Ping/ICMP is not a TCP or UDP port. true | false
ALLOW_REQUIRED_ICMP="[PUT_true_OR_false_HERE]"

# Services must be individually investigated and approved before inclusion.
APPROVED_SERVICES_TO_DISABLE=(
)

# Optional commands used only for POST-CHANGE verification. Each entry must be
# a complete local command reviewed by the operator. The script does not invent
# application credentials or expected content.
LOCAL_FUNCTIONAL_TEST_COMMANDS=(
    # Example structure only: "curl -fsS http://127.0.0.1/health"
)

# ==============================================================================
# LOCAL DOCUMENTATION PATHS
# ==============================================================================
CCDC_AUDIT="${CCDC_AUDIT:-/var/local/ccdc-audit}"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="$CCDC_AUDIT/script-runs/$RUN_ID"
BACKUP_DIR="$CCDC_AUDIT/backups/firewall/$RUN_ID"
LOG_FILE="$RUN_DIR/linux-hardening.log"
PLAN_FILE="$RUN_DIR/change-plan.txt"
UFW_STATUS_BACKUP="$BACKUP_DIR/ufw-status-numbered.txt"
UFW_USER_RULES_BACKUP="$BACKUP_DIR/user.rules"
UFW_USER6_RULES_BACKUP="$BACKUP_DIR/user6.rules"

ERRORS=0
WARNINGS=0
CHANGES=0
FAILED_CHANGES=0

log() {
    local level="$1"; shift
    local message="$*"
    printf '%s [%s] %s\n' "$(date -u +%FT%TZ)" "$level" "$message" | tee -a "$LOG_FILE"
}

pass() { log "PASS" "$*"; }
warn() { WARNINGS=$((WARNINGS + 1)); log "WARN" "$*"; }
fail() { ERRORS=$((ERRORS + 1)); log "FAIL" "$*"; }

is_true() { [[ "${1,,}" == "true" ]]; }
contains_placeholder() { [[ "$1" =~ \[PUT_.*_HERE\] ]]; }

require_root() {
    if [[ "$EUID" -ne 0 ]]; then
        printf '[-] Run as root: sudo bash %s %s\n' "$0" "$MODE" >&2
        exit 1
    fi
}

initialize_logs() {
    mkdir -p "$RUN_DIR" "$BACKUP_DIR" || {
        printf '[-] Could not create local audit directories under %s\n' "$CCDC_AUDIT" >&2
        exit 1
    }
    touch "$LOG_FILE" "$PLAN_FILE" || exit 1
    chmod 700 "$CCDC_AUDIT" "$RUN_DIR" "$BACKUP_DIR" 2>/dev/null || true
    chmod 600 "$LOG_FILE" "$PLAN_FILE" 2>/dev/null || true
}

validate_mode() {
    case "$MODE" in
        preflight|apply) pass "Execution mode accepted: $MODE" ;;
        *) fail "Invalid mode '$MODE'. Use preflight or apply." ;;
    esac

    case "$FIREWALL_MODE" in
        none|preserve|rebuild) pass "Firewall mode accepted: $FIREWALL_MODE" ;;
        *) fail "Invalid FIREWALL_MODE '$FIREWALL_MODE'." ;;
    esac
}

validate_required_profile() {
    local field value
    while IFS='|' read -r field value; do
        if [[ -z "$value" ]] || contains_placeholder "$value"; then
            fail "$field is incomplete."
        else
            pass "$field is populated."
        fi
    done <<EOF
TEAM_NUMBER|$TEAM_NUMBER
TARGET_HOSTNAME|$TARGET_HOSTNAME
TARGET_SERVER_ROLE|$TARGET_SERVER_ROLE
TARGET_PRIVATE_IP|$TARGET_PRIVATE_IP
TARGET_PUBLIC_IP|$TARGET_PUBLIC_IP
ALLOW_REQUIRED_ICMP|$ALLOW_REQUIRED_ICMP
VERIFIED_ADMIN_SSH_PORT|$VERIFIED_ADMIN_SSH_PORT
EOF

    case "$TARGET_SERVER_ROLE" in
        ecommerce|email|splunk) pass "Linux role accepted: $TARGET_SERVER_ROLE" ;;
        *) fail "TARGET_SERVER_ROLE must be ecommerce, email, or splunk." ;;
    esac

    case "${ALLOW_REQUIRED_ICMP,,}" in
        true|false) pass "ICMP decision is explicit." ;;
        *) fail "ALLOW_REQUIRED_ICMP must be true or false." ;;
    esac
}

validate_host_identity() {
    local actual_short actual_fqdn
    actual_short="$(hostname -s 2>/dev/null || true)"
    actual_fqdn="$(hostname -f 2>/dev/null || true)"

    if [[ "$TARGET_HOSTNAME" == "$actual_short" || "$TARGET_HOSTNAME" == "$actual_fqdn" ]]; then
        pass "Configured hostname matches this Linux host: $actual_short"
    else
        fail "Hostname mismatch. Configured='$TARGET_HOSTNAME'; actual='$actual_short'; FQDN='$actual_fqdn'."
    fi

    if command -v ip >/dev/null 2>&1; then
        if ip -o addr show | awk '{print $4}' | cut -d/ -f1 | grep -Fxq "$TARGET_PRIVATE_IP"; then
            pass "Configured private IP is assigned locally: $TARGET_PRIVATE_IP"
        else
            fail "Configured private IP is not assigned to this host: $TARGET_PRIVATE_IP"
        fi
    else
        fail "The ip command is unavailable; private-IP validation cannot run."
    fi
}

validate_port() {
    local port="$1"
    [[ "$port" =~ ^[0-9]+$ ]] && (( port >= 1 && port <= 65535 ))
}

validate_ports() {
    local port range start end
    declare -A seen_tcp=() seen_udp=()

    for port in "${VERIFIED_REQUIRED_TCP_PORTS[@]}"; do
        if validate_port "$port"; then
            if [[ -n "${seen_tcp[$port]:-}" ]]; then
                warn "Duplicate TCP port: $port"
            else
                seen_tcp[$port]=1
                pass "Valid required TCP port: $port"
            fi
        else
            fail "Invalid TCP port: '$port'"
        fi
    done

    for port in "${VERIFIED_REQUIRED_UDP_PORTS[@]}"; do
        if validate_port "$port"; then
            if [[ -n "${seen_udp[$port]:-}" ]]; then
                warn "Duplicate UDP port: $port"
            else
                seen_udp[$port]=1
                pass "Valid required UDP port: $port"
            fi
        else
            fail "Invalid UDP port: '$port'"
        fi
    done

    for range in "${VERIFIED_REQUIRED_TCP_RANGES[@]}"; do
        if [[ "$range" =~ ^([0-9]+):([0-9]+)$ ]]; then
            start="${BASH_REMATCH[1]}"; end="${BASH_REMATCH[2]}"
            if validate_port "$start" && validate_port "$end" && (( start <= end )); then
                pass "Valid required TCP range: $range"
            else
                fail "Invalid TCP range: '$range'"
            fi
        else
            fail "TCP range must use start:end format: '$range'"
        fi
    done

    if [[ "$VERIFIED_ADMIN_SSH_PORT" != "none" ]]; then
        if validate_port "$VERIFIED_ADMIN_SSH_PORT"; then
            pass "Verified administrative SSH port: $VERIFIED_ADMIN_SSH_PORT"
        else
            fail "VERIFIED_ADMIN_SSH_PORT must be 1-65535 or 'none'."
        fi
    fi

    if ((${#VERIFIED_REQUIRED_TCP_PORTS[@]} == 0 && ${#VERIFIED_REQUIRED_UDP_PORTS[@]} == 0 && ${#VERIFIED_REQUIRED_TCP_RANGES[@]} == 0)); then
        warn "No required TCP ports, UDP ports, or TCP ranges are configured. Confirm this is intentional."
    fi
}

validate_service_approvals() {
    local service
    for service in "${APPROVED_SERVICES_TO_DISABLE[@]}"; do
        if [[ -z "$service" ]] || contains_placeholder "$service"; then
            fail "Invalid approved-service entry: '$service'"
        elif [[ ! "$service" =~ ^[A-Za-z0-9_.@:-]+$ ]]; then
            fail "Unsafe service-unit characters in: '$service'"
        else
            pass "Approved service-disable entry is syntactically valid: $service"
        fi
    done
}

detect_firewall() {
    if command -v ufw >/dev/null 2>&1; then
        pass "UFW is installed."
        ufw status verbose 2>&1 | tee -a "$LOG_FILE" || warn "Could not read UFW status."
    else
        if [[ "$FIREWALL_MODE" == "none" ]]; then
            warn "UFW is not installed; firewall mode none will make no change."
        else
            fail "UFW is required for firewall mode '$FIREWALL_MODE' but is not installed."
        fi
    fi

    if command -v firewall-cmd >/dev/null 2>&1; then
        warn "firewalld tooling is present. This master script applies only UFW changes; investigate firewall ownership."
    fi
    if command -v nft >/dev/null 2>&1; then
        log "INFO" "nft command is present. Review the live ruleset for interactions with UFW."
    fi
}

show_discovery() {
    log "INFO" "Current listeners (read-only):"
    if command -v ss >/dev/null 2>&1; then
        ss -lntup 2>&1 | tee -a "$LOG_FILE" || warn "Listener discovery failed."
    else
        warn "ss is unavailable; listener discovery was not performed."
    fi

    log "INFO" "Running services (read-only):"
    if command -v systemctl >/dev/null 2>&1; then
        systemctl --no-pager --type=service --state=running 2>&1 | tee -a "$LOG_FILE" || warn "Service discovery failed."
    else
        warn "systemctl is unavailable; service discovery was not performed."
    fi
}

write_plan() {
    {
        echo "CCDC Linux hardening change plan"
        echo "Script version: $SCRIPT_VERSION"
        echo "Run ID: $RUN_ID"
        echo "Mode: $MODE"
        echo "Team: $TEAM_NUMBER"
        echo "Hostname: $TARGET_HOSTNAME"
        echo "Role: $TARGET_SERVER_ROLE"
        echo "Private IP: $TARGET_PRIVATE_IP"
        echo "Public/NAT IP: $TARGET_PUBLIC_IP"
        echo "Firewall mode: $FIREWALL_MODE"
        echo "Required TCP ports: ${VERIFIED_REQUIRED_TCP_PORTS[*]:-(none)}"
        echo "Required UDP ports: ${VERIFIED_REQUIRED_UDP_PORTS[*]:-(none)}"
        echo "Required TCP ranges: ${VERIFIED_REQUIRED_TCP_RANGES[*]:-(none)}"
        echo "ICMP required: $ALLOW_REQUIRED_ICMP"
        echo "Administrative SSH port: $VERIFIED_ADMIN_SSH_PORT"
        echo "Administrative source ranges: ${VERIFIED_ADMIN_SOURCE_RANGES[*]:-(none)}"
        echo "Approved services to disable: ${APPROVED_SERVICES_TO_DISABLE[*]:-(none)}"
        echo "Host profile approved: $HOST_PROFILE_APPROVED"
        echo "Firewall profile approved: $FIREWALL_PROFILE_APPROVED"
        echo "Firewall rebuild approved: $FIREWALL_REBUILD_APPROVED"
        echo "Console recovery confirmed: $CONSOLE_RECOVERY_CONFIRMED"
        echo "Rollback reviewed: $ROLLBACK_REVIEWED"
    } | tee "$PLAN_FILE"
    chmod 600 "$PLAN_FILE" 2>/dev/null || true
}

validate_apply_approvals() {
    [[ "$MODE" == "apply" ]] || return 0

    is_true "$HOST_PROFILE_APPROVED" || fail "Apply mode requires HOST_PROFILE_APPROVED=true."
    is_true "$ROLLBACK_REVIEWED" || fail "Apply mode requires ROLLBACK_REVIEWED=true."

    if [[ "$FIREWALL_MODE" != "none" ]]; then
        is_true "$FIREWALL_PROFILE_APPROVED" || fail "Firewall changes require FIREWALL_PROFILE_APPROVED=true."
        is_true "$CONSOLE_RECOVERY_CONFIRMED" || fail "Firewall changes require CONSOLE_RECOVERY_CONFIRMED=true."
    fi

    if [[ "$FIREWALL_MODE" == "rebuild" ]]; then
        is_true "$FIREWALL_REBUILD_APPROVED" || fail "Rebuild requires FIREWALL_REBUILD_APPROVED=true."
    fi
}

backup_ufw() {
    [[ "$FIREWALL_MODE" != "none" ]] || return 0

    log "INFO" "Backing up current UFW state locally."
    if ufw status numbered > "$UFW_STATUS_BACKUP" 2>&1; then
        pass "Saved UFW status to $UFW_STATUS_BACKUP"
    else
        fail "Could not save UFW status."
        return 1
    fi

    if [[ -f /etc/ufw/user.rules ]]; then
        cp -a /etc/ufw/user.rules "$UFW_USER_RULES_BACKUP" || { fail "Could not back up user.rules."; return 1; }
        pass "Backed up /etc/ufw/user.rules"
    fi
    if [[ -f /etc/ufw/user6.rules ]]; then
        cp -a /etc/ufw/user6.rules "$UFW_USER6_RULES_BACKUP" || { fail "Could not back up user6.rules."; return 1; }
        pass "Backed up /etc/ufw/user6.rules"
    fi
    sync
}

run_change() {
    local description="$1"; shift
    log "CHANGE" "$description"
    if "$@" >>"$LOG_FILE" 2>&1; then
        CHANGES=$((CHANGES + 1))
        pass "$description"
        return 0
    else
        FAILED_CHANGES=$((FAILED_CHANGES + 1))
        fail "$description"
        return 1
    fi
}

ufw_rule_exists() {
    local pattern="$1"
    ufw status 2>/dev/null | grep -Fq "$pattern"
}

apply_ufw_permits() {
    local port range source

    # Preserve administrative access before restrictive defaults.
    if [[ "$VERIFIED_ADMIN_SSH_PORT" != "none" ]]; then
        if ((${#VERIFIED_ADMIN_SOURCE_RANGES[@]} > 0)); then
            for source in "${VERIFIED_ADMIN_SOURCE_RANGES[@]}"; do
                run_change "Allow SSH TCP $VERIFIED_ADMIN_SSH_PORT from $source" \
                    ufw allow from "$source" to any port "$VERIFIED_ADMIN_SSH_PORT" proto tcp || return 1
            done
        else
            run_change "Allow verified administrative SSH TCP $VERIFIED_ADMIN_SSH_PORT" \
                ufw allow "$VERIFIED_ADMIN_SSH_PORT"/tcp || return 1
        fi
    fi

    for port in "${VERIFIED_REQUIRED_TCP_PORTS[@]}"; do
        run_change "Allow required TCP port $port" ufw allow "$port"/tcp || return 1
    done
    for port in "${VERIFIED_REQUIRED_UDP_PORTS[@]}"; do
        run_change "Allow required UDP port $port" ufw allow "$port"/udp || return 1
    done
    for range in "${VERIFIED_REQUIRED_TCP_RANGES[@]}"; do
        run_change "Allow required TCP range $range" ufw allow "$range"/tcp || return 1
    done

    if is_true "$ALLOW_REQUIRED_ICMP"; then
        warn "ICMP is required. UFW ICMP behavior depends on /etc/ufw/before.rules; this script does not rewrite that file automatically. Verify ping manually."
    fi
}

apply_firewall() {
    case "$FIREWALL_MODE" in
        none)
            log "INFO" "FIREWALL_MODE=none; no host-firewall changes will be made."
            ;;
        preserve)
            backup_ufw || return 1
            apply_ufw_permits || return 1
            run_change "Enable UFW after adding verified permits" ufw --force enable || return 1
            ;;
        rebuild)
            backup_ufw || return 1
            run_change "Reset UFW for separately approved rebuild" ufw --force reset || return 1
            run_change "Set UFW default deny incoming" ufw default deny incoming || return 1
            run_change "Set UFW default allow outgoing" ufw default allow outgoing || return 1
            apply_ufw_permits || return 1
            run_change "Enable rebuilt UFW policy" ufw --force enable || return 1
            ;;
    esac
}

apply_service_disables() {
    local service
    for service in "${APPROVED_SERVICES_TO_DISABLE[@]}"; do
        run_change "Stop approved service $service" systemctl stop "$service" || return 1
        run_change "Disable approved service $service" systemctl disable "$service" || return 1
    done
}

verify_after_changes() {
    local test_command
    log "INFO" "Post-change UFW status:"
    if command -v ufw >/dev/null 2>&1; then
        ufw status verbose 2>&1 | tee -a "$LOG_FILE" || fail "Could not read post-change UFW status."
    fi

    log "INFO" "Post-change listeners:"
    ss -lntup 2>&1 | tee -a "$LOG_FILE" || fail "Could not collect post-change listeners."

    for test_command in "${LOCAL_FUNCTIONAL_TEST_COMMANDS[@]}"; do
        log "TEST" "$test_command"
        if bash -o pipefail -c "$test_command" >>"$LOG_FILE" 2>&1; then
            pass "Local functional test passed: $test_command"
        else
            fail "Local functional test failed: $test_command"
        fi
    done

    warn "Manual verification is still required from a second authorized competition VM and the scoring dashboard."
}

print_rollback_guidance() {
    [[ "$FIREWALL_MODE" != "none" ]] || return 0
    cat <<EOF | tee -a "$LOG_FILE"

ROLLBACK REFERENCE
------------------
UFW status record: $UFW_STATUS_BACKUP
UFW IPv4 rules backup: $UFW_USER_RULES_BACKUP
UFW IPv6 rules backup: $UFW_USER6_RULES_BACKUP

If firewall verification fails, keep the original administrative session open.
Use the NETLAB console and the event-approved rollback procedure. Restoring the
saved UFW rule files should be performed deliberately, followed by 'ufw reload'
and complete service/access verification. This script does not auto-rollback
because automatic restoration could overwrite evidence or a teammate's changes.
EOF
}

main() {
    require_root
    initialize_logs
    log "INFO" "Starting CCDC Linux master script version $SCRIPT_VERSION in $MODE mode."

    validate_mode
    validate_required_profile
    validate_host_identity
    validate_ports
    validate_service_approvals
    detect_firewall
    show_discovery
    write_plan
    validate_apply_approvals

    if ((ERRORS > 0)); then
        log "FAIL" "PREFLIGHT FAIL: $ERRORS error(s), $WARNINGS warning(s). No changes were made."
        exit 1
    fi

    if [[ "$MODE" == "preflight" ]]; then
        log "PASS" "PREFLIGHT PASS: $WARNINGS warning(s). No changes were made."
        exit 0
    fi

    log "INFO" "Preflight passed. Beginning approved apply actions."
    apply_firewall || true

    if ((ERRORS == 0)); then
        apply_service_disables || true
    else
        warn "Skipping service changes because a prior apply action failed."
    fi

    verify_after_changes
    print_rollback_guidance

    if ((ERRORS > 0 || FAILED_CHANGES > 0)); then
        log "FAIL" "APPLY INCOMPLETE: $CHANGES successful change(s), $FAILED_CHANGES failed change(s), $ERRORS total error(s). Review $LOG_FILE"
        exit 1
    fi

    log "PASS" "APPLY COMPLETE: $CHANGES change(s) succeeded. Manual remote, functional, and scoring verification remains required."
}

main "$@"
