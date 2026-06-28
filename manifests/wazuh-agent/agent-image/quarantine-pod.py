#!/usr/bin/python3
"""Wazuh Active Response handler for lab pod quarantine labeling."""
import os
import sys
import json
import datetime
from pathlib import PureWindowsPath, PurePosixPath

try:
    import kubernetes
except ImportError:
    kubernetes = None

LOG_FILE = os.environ.get("WAZUH_AR_LOG_FILE", "/var/ossec/logs/active-responses.log")
ADD_COMMAND, DELETE_COMMAND = 0, 1
OS_SUCCESS, OS_INVALID = 0, -1
OS_API_ERROR = 1
ALLOWED_NAMESPACES = {"vulnerable-apps"}
QUARANTINE_LABEL = "security.watergon/quarantine"


def write_debug_file(ar_name, msg):
    try:
        with open(LOG_FILE, mode="a") as f:
            active_response_pos = ar_name.find("active-response")
            log_name = ar_name[active_response_pos:] if active_response_pos >= 0 else ar_name
            ar_name_posix = str(PurePosixPath(PureWindowsPath(log_name)))
            f.write(
                str(datetime.datetime.now().strftime('%Y/%m/%d %H:%M:%S'))
                + " " + ar_name_posix + ": " + msg + "\n")
    except OSError:
        print(msg, file=sys.stderr)


def nested_get(data, path):
    current = data
    for key in path:
        if not isinstance(current, dict) or key not in current:
            return None
        current = current[key]
    return current


def extract_alert(data):
    return nested_get(data, ["parameters", "alert"]) or data.get("alert") or data


def extract_pod_context(data):
    alert = extract_alert(data)
    pod = (
        nested_get(alert, ["data", "process_exec", "process", "pod"])
        or nested_get(alert, ["data", "process", "pod"])
        or nested_get(alert, ["process_exec", "process", "pod"])
        or {}
    )
    return {
        "namespace": pod.get("namespace") or nested_get(alert, ["kubernetes", "namespace"]),
        "pod": pod.get("name") or nested_get(alert, ["kubernetes", "pod_name"]),
        "rule_id": str(nested_get(alert, ["rule", "id"]) or alert.get("rule_id") or "unknown"),
    }


def setup_and_check_message(argv):
    input_str = ""
    for line in sys.stdin:
        input_str = line
        break
    write_debug_file(argv[0], input_str)
    try:
        data = json.loads(input_str)
    except ValueError:
        write_debug_file(argv[0], "invalid JSON")
        return OS_INVALID, {}
    if data.get("command") == "add":
        return ADD_COMMAND, data
    if data.get("command") == "delete":
        return DELETE_COMMAND, data
    write_debug_file(argv[0], "bad command: " + str(data.get("command")))
    return OS_INVALID, data


def patch_pod_label(api, namespace, pod, value):
    body = {"metadata": {"labels": {QUARANTINE_LABEL: value}}}
    api.patch_namespaced_pod(name=pod, namespace=namespace, body=body)


def main(argv):
    write_debug_file(argv[0], "Started")
    command, data = setup_and_check_message(argv)
    if command < 0:
        sys.exit(OS_INVALID)

    context = extract_pod_context(data)
    namespace = context["namespace"]
    pod = context["pod"]
    rule_id = context["rule_id"]
    if not namespace or not pod:
        write_debug_file(argv[0], f"missing namespace or pod in alert rule={rule_id}; no action")
        sys.exit(OS_SUCCESS)
    if namespace not in ALLOWED_NAMESPACES:
        write_debug_file(argv[0], f"refusing quarantine outside allowlist: {namespace}/{pod} rule={rule_id}")
        sys.exit(OS_SUCCESS)

    value = "true" if command == ADD_COMMAND else "false"
    try:
        if "WAZUH_AR_DRY_RUN" in os.environ:
            write_debug_file(argv[0], f"dry-run quarantine label {namespace}/{pod}={value}")
        else:
            if kubernetes is None:
                raise RuntimeError("kubernetes client is not installed")
            kubernetes.config.load_incluster_config()
            api = kubernetes.client.CoreV1Api()
            patch_pod_label(api, namespace, pod, value)
        write_debug_file(argv[0], f"OK quarantine {namespace}/{pod}={value} rule={rule_id}")
    except Exception as e:
        write_debug_file(argv[0], f"err: {e}")
        sys.exit(OS_API_ERROR)
    write_debug_file(argv[0], "Ended")
    sys.exit(OS_SUCCESS)


if __name__ == "__main__":
    main(sys.argv)
