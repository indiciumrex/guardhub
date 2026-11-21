import yaml
import requests


def load(path: str) -> dict:
    with open(path) as f:
        return yaml.safe_load(f)
