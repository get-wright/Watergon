#!/usr/bin/python3
"""Wazuh Active Response handler for deleting lab pods.

The script reads one Wazuh Active Response JSON document from stdin. It only
deletes pods in the vulnerable-apps namespace and exits safely when the alert
does not contain enough Kubernetes context.
"""
import sys
import json
import datetime
import os
from pathlib import PureWindowsPath, PurePosixPath

try:
    import kubernetes
except ImportError:
    kubernetes = None

LOG_FILE = os.environ.get("WAZUH_AR_LOG_FILE", "/var/ossec/logs/active-responses.log")
ADD_COMMAND, DELETE_COMMAND, CONTINUE_COMMAND, ABORT_COMMAND = 0, 1, 2, 3
OS_SUCCESS, OS_INVALID = 0, -1
OS_API_ERROR = 1
ALLOWED_NAMESPACE = "vulnerable-apps"


class Message:
    def __init__(self):
        self.alert = {}
        self.command = OS_INVALID


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
    process = (
        nested_get(alert, ["data", "process_exec", "process"])
        or nested_get(alert, ["data", "process"])
        or nested_get(alert, ["process_exec", "process"])
        or {}
    )
    return {
        "namespace": pod.get("namespace") or nested_get(alert, ["kubernetes", "namespace"]),
        "pod": pod.get("name") or nested_get(alert, ["kubernetes", "pod_name"]),
        "container": process.get("container", {}).get("name") if isinstance(process.get("container"), dict) else process.get("container_name"),
        "rule_id": str(nested_get(alert, ["rule", "id"]) or alert.get("rule_id") or "unknown"),
    }


def setup_and_check_message(argv):
    input_str = ""
    for line in sys.stdin:
        input_str = line
        break
    write_debug_file(argv[0], input_str)
    msg = Message()
    try:
        data = json.loads(input_str)
    except ValueError:
        write_debug_file(argv[0], 'invalid JSON')
        return msg
    msg.alert = data
    cmd = data.get("command")
    if cmd == "add":
        msg.command = ADD_COMMAND
    elif cmd == "delete":
        msg.command = DELETE_COMMAND
    else:
        write_debug_file(argv[0], 'bad command: ' + str(cmd))
    return msg


def main(argv):
    write_debug_file(argv[0], "Started")
    msg = setup_and_check_message(argv)
    if msg.command < 0:
        sys.exit(OS_INVALID)
    if msg.command == ADD_COMMAND:
        context = extract_pod_context(msg.alert)
        ns = context["namespace"]
        pod = context["pod"]
        container = context["container"] or "unknown-container"
        rule_id = context["rule_id"]
        if not ns or not pod:
            write_debug_file(argv[0], f"missing namespace or pod in alert rule={rule_id}; no action")
            sys.exit(OS_SUCCESS)
        if ns != ALLOWED_NAMESPACE:
            write_debug_file(argv[0], f"refusing delete outside {ALLOWED_NAMESPACE}: {ns}/{pod} rule={rule_id}")
            sys.exit(OS_SUCCESS)
        try:
            write_debug_file(argv[0], f"Deleting {ns}/{pod} container={container} rule={rule_id}")
            if "WAZUH_AR_DRY_RUN" in os.environ:
                write_debug_file(argv[0], f"dry-run delete {ns}/{pod}")
            else:
                if kubernetes is None:
                    raise RuntimeError("kubernetes client is not installed")
                kubernetes.config.load_incluster_config()
                kubernetes.client.CoreV1Api().delete_namespaced_pod(namespace=ns, name=pod)
            write_debug_file(argv[0], f"OK {ns}/{pod}")
        except Exception as e:
            write_debug_file(argv[0], f"err: {e}")
            sys.exit(OS_API_ERROR)
    write_debug_file(argv[0], "Ended")
    sys.exit(OS_SUCCESS)


if __name__ == "__main__":
    main(sys.argv)
