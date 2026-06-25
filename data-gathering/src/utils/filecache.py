# We want aggressive caching for items like WHOIS and TI

import json
from pathlib import Path
from typing import Any, Callable, Dict, List, Type, TypeVar

from proxyrecord import IpRecord

T = TypeVar("T")

Serializer = Callable[[Any], Dict[str, Any]]
Deserializer = Callable[[Dict[str, Any]], Any]

conversions: Dict[type, Dict[str, Callable]] = {
    IpRecord: {
        "serialize": lambda obj: obj.serialize(),
        "deserialize": IpRecord.deserialize,
    }
}


def write_list_to_file(path: str | Path, items: List[T]) -> None:
    """
    Save a homogeneous list of objects to disk.

    - Ensures all items have the same class.
    - Uses `conversions` to pick the right serializer.
    - Stores a small class marker in the file for sanity-checking.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    if not items:
        # You can also choose to avoid writing anything for empty lists
        data = {"class": None, "items": []}
        path.write_text(json.dumps(data))
        return

    cls = type(items[0])
    if not all(isinstance(i, cls) for i in items):
        raise TypeError("All items in the list must be of the same type")

    if cls not in conversions:
        raise ValueError(f"No (de)serializer registered for class {cls!r}")

    serializer: Serializer = conversions[cls]["serialize"]

    payload = {
        "class": f"{cls.__module__}.{cls.__qualname__}",
        "items": [serializer(obj) for obj in items],
    }

    path.write_text(json.dumps(payload))


def read_list_from_file(path: str | Path, cls: Type[T]) -> List[T]:
    """
    Load a list of objects of type `cls` from disk.

    - Uses filename + explicit `cls` to choose the deserializer.
    """
    path = Path(path)
    if not path.exists():
        return []
    raw = json.loads(path.read_text())

    if cls not in conversions:
        raise ValueError(f"No (de)serializer registered for class {cls!r}")

    stored_class = raw.get("class")
    expected_class = f"{cls.__module__}.{cls.__qualname__}"
    if stored_class is not None and stored_class != expected_class:
        raise ValueError(
            f"File was written for {stored_class}, but {expected_class} was requested"
        )

    deserializer: Deserializer = conversions[cls]["deserialize"]
    return [deserializer(item) for item in raw.get("items", [])]
