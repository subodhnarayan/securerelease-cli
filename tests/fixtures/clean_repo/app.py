"""Safe fixture used to check for false positives."""
import json
import subprocess

import yaml


def load_config(raw):
    return yaml.safe_load(raw)


def list_directory(name):
    return subprocess.run(["ls", "--", name], check=False, capture_output=True)


def parse(payload):
    return json.loads(payload)
