#!/bin/bash
set -euo pipefail

LOG_FILE="${WAZUH_AR_LOG_FILE:-/var/ossec/logs/active-responses.log}"
NODEPORT="${WATERGON_DVWA_NODEPORT:-30000}"
DENY_CIDRS="${WATERGON_BLOCK_DENY_CIDRS:-127.0.0.0/8,10.96.0.0/12,10.244.0.0/16,169.254.0.0/16,224.0.0.0/4}"

log_msg() {
  local message="$1"
  local timestamp
  timestamp="$(date '+%Y/%m/%d %H:%M:%S')"
  if ! printf '%s %s: %s\n' "$timestamp" "$0" "$message" >> "$LOG_FILE" 2>/dev/null; then
    printf '%s\n' "$message" >&2
  fi
}

read_payload() {
  local line=""
  IFS= read -r line || true
  printf '%s' "$line"
}

extract_source_ip() {
  python3 -c '
import json
import ipaddress
import re
import sys

def nested_get(data, path):
    current = data
    for key in path:
        if not isinstance(current, dict) or key not in current:
            return None
        current = current[key]
    return current

data = json.loads(sys.stdin.read())
alert = nested_get(data, ["parameters", "alert"]) or data.get("alert") or data
candidates = [
    nested_get(alert, ["data", "srcip"]),
    nested_get(alert, ["data", "src_ip"]),
    nested_get(alert, ["data", "source", "ip"]),
    nested_get(alert, ["data", "network", "src_ip"]),
    nested_get(alert, ["data", "process_exec", "process", "arguments"]),
    alert.get("srcip"),
    alert.get("src_ip"),
]
for candidate in candidates:
    if candidate:
        for value in re.findall(r"(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9.])", str(candidate)):
            try:
                ipaddress.ip_address(value)
            except ValueError:
                continue
            print(value)
            raise SystemExit(0)
' <<< "$1"
}

extract_rule_id() {
  python3 -c '
import json
import sys

def nested_get(data, path):
    current = data
    for key in path:
        if not isinstance(current, dict) or key not in current:
            return None
        current = current[key]
    return current

data = json.loads(sys.stdin.read())
alert = nested_get(data, ["parameters", "alert"]) or data.get("alert") or data
print(nested_get(alert, ["rule", "id"]) or alert.get("rule_id") or "unknown")
' <<< "$1"
}

validate_ip() {
  python3 -c '
import ipaddress
import sys
ipaddress.ip_address(sys.argv[1])
' "$1"
}

reject_denied_ip() {
  python3 -c '
import ipaddress
import sys
ip = ipaddress.ip_address(sys.argv[1])
for cidr in filter(None, sys.argv[2].split(",")):
    if ip in ipaddress.ip_network(cidr.strip(), strict=False):
        raise SystemExit(1)
' "$1" "$DENY_CIDRS"
}

rule_exists() {
  iptables -C INPUT -p tcp --dport "$NODEPORT" -s "$1" -j DROP >/dev/null 2>&1
}

add_rule() {
  iptables -I INPUT -p tcp --dport "$NODEPORT" -s "$1" -j DROP
}

delete_rule() {
  iptables -D INPUT -p tcp --dport "$NODEPORT" -s "$1" -j DROP
}

main() {
  local payload command source_ip rule_id
  payload="$(read_payload)"
  log_msg "$payload"
  command="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read()).get("command", ""))' <<< "$payload")"
  source_ip="$(extract_source_ip "$payload" | tr -d '[:space:]')"
  rule_id="$(extract_rule_id "$payload" | tr -d '[:space:]')"

  if [[ "$command" != "add" && "$command" != "delete" ]]; then
    log_msg "bad command: $command rule=$rule_id"
    exit 255
  fi
  if [[ -z "$source_ip" ]] || ! validate_ip "$source_ip"; then
    log_msg "invalid or missing source IP: $source_ip rule=$rule_id"
    exit 0
  fi
  if ! reject_denied_ip "$source_ip"; then
    log_msg "refusing to block protected lab infrastructure IP: $source_ip rule=$rule_id"
    exit 0
  fi

  if [[ -n "${WAZUH_AR_DRY_RUN:-}" ]]; then
    log_msg "dry-run $command iptables block source=$source_ip dport=$NODEPORT rule=$rule_id"
    exit 0
  fi

  if [[ "$command" == "add" ]]; then
    if rule_exists "$source_ip"; then
      log_msg "iptables block already exists source=$source_ip dport=$NODEPORT rule=$rule_id"
    else
      add_rule "$source_ip"
      log_msg "added timed iptables block source=$source_ip dport=$NODEPORT rule=$rule_id"
    fi
  else
    if rule_exists "$source_ip"; then
      delete_rule "$source_ip"
      log_msg "removed timed iptables block source=$source_ip dport=$NODEPORT rule=$rule_id"
    else
      log_msg "iptables block absent source=$source_ip dport=$NODEPORT rule=$rule_id"
    fi
  fi
}

main "$@"
