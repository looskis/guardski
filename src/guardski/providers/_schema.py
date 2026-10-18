from __future__ import annotations

# Minimal, dependency-free JSON Schema validation for the subset we emit and rely on.
# It is used for model-output structural validation and the single repair turn
# (SPEC §4.2.2). It is deliberately small: policies are enforced in `policy.py`, not here.


def validate(instance: object, schema: dict, path: str = "$") -> list[str]:
    errors: list[str] = []
    if "anyOf" in schema:
        if not any(not validate(instance, branch, path) for branch in schema["anyOf"]):
            errors.append(f"{path}: does not match any allowed shape")
        return errors
    expected = schema.get("type")
    if expected is not None and not _is_type(instance, expected):
        return [f"{path}: expected {expected}, got {_type_name(instance)}"]
    if "enum" in schema and instance not in schema["enum"]:
        errors.append(f"{path}: must be one of {schema['enum']}")
    if isinstance(instance, dict):
        for key in schema.get("required", []):
            if key not in instance:
                errors.append(f"{path}.{key}: is required")
        properties = schema.get("properties", {})
        for key, value in instance.items():
            if key in properties:
                errors.extend(validate(value, properties[key], f"{path}.{key}"))
            elif schema.get("additionalProperties") is False:
                errors.append(f"{path}.{key}: additional property not allowed")
    if isinstance(instance, list) and "items" in schema:
        for index, item in enumerate(instance):
            errors.extend(validate(item, schema["items"], f"{path}[{index}]"))
    return errors


def _is_type(value: object, expected: str) -> bool:
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "null":
        return value is None
    return True


def _type_name(value: object) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return type(value).__name__
