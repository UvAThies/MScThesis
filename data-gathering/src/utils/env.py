import os
from collections.abc import Iterable
from typing import TypeVar

from dotenv import load_dotenv

load_dotenv()


K = TypeVar("K", bound=str)


def ensure(items: Iterable[K]) -> dict[K, str]:
    """
    Ensure all given env vars exist.
    Returns a dict {name: value} or raises an error if any are missing.
    """
    result: dict[K, str] = {}
    missing: list[K] = []

    for name in items:
        value = os.getenv(name)
        if value is None:
            missing.append(name)
        else:
            result[name] = value

    if missing:
        raise EnvironmentError(f"Missing environment variables: {', '.join(missing)}")

    return result
