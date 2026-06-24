import re


def to_k8s_name(value: str, max_length: int = 253) -> str:
    """
    Convert arbitrary text into a Kubernetes-safe resource name.

    Kubernetes object names must generally be DNS-label compatible:
    lowercase alphanumeric characters and '-'.
    """
    value = value.lower()
    value = re.sub(r"[^a-z0-9-]+", "-", value)
    value = value.strip("-")
    return value[:max_length] or "unnamed"


def image_uses_latest_or_no_tag(image: str) -> bool:
    """
    Detect images using ':latest' or no explicit tag.

    Examples:
      nginx              -> bad
      nginx:latest       -> bad
      nginx:1.25         -> okay
      repo/app@sha256:x  -> okay
    """
    if "@sha256:" in image:
        return False

    last_part = image.split("/")[-1]

    if ":" not in last_part:
        return True

    return image.endswith(":latest")