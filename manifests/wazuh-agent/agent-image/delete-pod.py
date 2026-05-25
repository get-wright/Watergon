#!/usr/bin/python3
"""Wazuh Active Response handler that deletes the offending pod
identified in a Tetragon process_exec alert via the in-cluster
Kubernetes API."""
import os
import sys
import json
import datetime
from pathlib import PureWindowsPath, PurePosixPath

try:
    import kubernetes
except ImportError:
    pass

LOG_FILE = "/var/ossec/logs/active-responses.log"
ADD_COMMAND, DELETE_COMMAND, CONTINUE_COMMAND, ABORT_COMMAND = 0, 1, 2, 3
OS_SUCCESS, OS_INVALID = 0, -1


class message:
    def __init__(self):
        self.alert = ""
        self.command = 0


def write_debug_file(ar_name, msg):
    with open(LOG_FILE, mode="a") as f:
        ar_name_posix = str(PurePosixPath(PureWindowsPath(
            ar_name[ar_name.find("active-response"):])))
        f.write(
            str(datetime.datetime.now().strftime('%Y/%m/%d %H:%M:%S'))
            + " " + ar_name_posix + ": " + msg + "\n")


def setup_and_check_message(argv):
    input_str = ""
    for line in sys.stdin:
        input_str = line
        break
    write_debug_file(argv[0], input_str)
    try:
        data = json.loads(input_str)
    except ValueError:
        write_debug_file(argv[0], 'invalid JSON')
        message.command = OS_INVALID
        return message
    message.alert = data
    cmd = data.get("command")
    if cmd == "add":
        message.command = ADD_COMMAND
    elif cmd == "delete":
        message.command = DELETE_COMMAND
    else:
        message.command = OS_INVALID
        write_debug_file(argv[0], 'bad command: ' + str(cmd))
    return message


def main(argv):
    write_debug_file(argv[0], "Started")
    msg = setup_and_check_message(argv)
    if msg.command < 0:
        sys.exit(OS_INVALID)
    if msg.command == ADD_COMMAND:
        alert = msg.alert["parameters"]["alert"]
        pod = alert["data"]["process_exec"]["process"]["pod"]["name"]
        ns = alert["data"]["process_exec"]["process"]["pod"]["namespace"]
        try:
            kubernetes.config.load_incluster_config()
            write_debug_file(argv[0], f"Deleting {ns}/{pod}")
            kubernetes.client.CoreV1Api().delete_namespaced_pod(namespace=ns, name=pod)
            write_debug_file(argv[0], f"OK {ns}/{pod}")
        except Exception as e:
            write_debug_file(argv[0], f"err: {e}")
    write_debug_file(argv[0], "Ended")
    sys.exit(OS_SUCCESS)


if __name__ == "__main__":
    main(sys.argv)
