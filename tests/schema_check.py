"""A minimal JSON Schema validator for the subset schemas/action-plan.schema.json uses.

Supported keywords: type (one name or a list, including "null"), required, properties,
items, enum, additionalProperties (false, or a schema for the extra values), pattern, and local "$ref" to "#/$defs/<name>".
Anything else in a schema is ignored.
"""
from __future__ import annotations

import re

_TYPES = {
    "object": lambda v: isinstance(v, dict),
    "array": lambda v: isinstance(v, list),
    "string": lambda v: isinstance(v, str),
    "boolean": lambda v: isinstance(v, bool),
    "null": lambda v: v is None,
    # bool is an int subclass in Python but never a JSON number
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
}


def _resolve(ref: str, root: dict) -> dict:
    if not ref.startswith("#/$defs/"):
        raise ValueError("unsupported $ref: %s" % ref)
    return root["$defs"][ref[len("#/$defs/"):]]


def _check(value, schema: dict, root: dict, path: str, errors: list) -> None:
    if "$ref" in schema:
        schema = _resolve(schema["$ref"], root)
    if "type" in schema:
        names = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        if not any(_TYPES[n](value) for n in names):
            errors.append("%s: expected %s, got %s" % (path, "/".join(names), type(value).__name__))
            return
    if "enum" in schema and value not in schema["enum"]:
        errors.append("%s: %r is not one of %s" % (path, value, schema["enum"]))
    if "pattern" in schema and isinstance(value, str) and not re.search(schema["pattern"], value):
        errors.append("%s: %r does not match %s" % (path, value, schema["pattern"]))
    if isinstance(value, dict):
        for name in schema.get("required", []):
            if name not in value:
                errors.append("%s: missing required property %s" % (path, name))
        props = schema.get("properties", {})
        for name, sub in value.items():
            if name in props:
                _check(sub, props[name], root, "%s.%s" % (path, name), errors)
            elif schema.get("additionalProperties") is False:
                errors.append("%s: unexpected property %s" % (path, name))
            elif isinstance(schema.get("additionalProperties"), dict):
                _check(sub, schema["additionalProperties"], root, "%s.%s" % (path, name), errors)
    if isinstance(value, list) and "items" in schema:
        for i, sub in enumerate(value):
            _check(sub, schema["items"], root, "%s[%d]" % (path, i), errors)


def validate(instance, schema: dict) -> list:
    """Error messages for instance against schema; [] when it conforms."""
    errors: list = []
    _check(instance, schema, schema, "$", errors)
    return errors
