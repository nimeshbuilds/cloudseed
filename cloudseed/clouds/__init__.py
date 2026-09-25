from .base import Cloud, Question  # noqa: F401  (Question is re-exported: clouds.Question)
from .aws import AWS
from .gcp import GCP
from .azure import Azure
from .vmware import VMware

CLOUDS: dict[str, Cloud] = {c.key: c for c in (AWS(), GCP(), Azure(), VMware())}


def get(key: str) -> Cloud:
    if key not in CLOUDS:
        raise KeyError(key)
    return CLOUDS[key]
