"""Minimal OpenAPI 3.x / Swagger 2.0 reader used to drive the API scanner."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

MAX_SPEC_BYTES = 5 * 1024 * 1024
HTTP_METHODS = ("get", "put", "post", "delete", "patch", "head", "options")
DISCOVERY_PATHS = (
    "/openapi.json", "/swagger.json", "/v3/api-docs", "/api-docs", "/openapi.yaml",
    "/swagger/v1/swagger.json", "/api/openapi.json", "/docs/openapi.json",
)


class SpecError(ValueError):
    """The specification could not be read or is not an OpenAPI/Swagger document."""


@dataclass(slots=True)
class Param:
    name: str
    location: str
    required: bool
    schema: dict[str, Any]


@dataclass(slots=True)
class Operation:
    method: str
    path: str
    operation_id: str
    params: list[Param]
    secured: bool
    deprecated: bool
    body_schema: dict[str, Any] | None
    responses: list[str]

    @property
    def key(self) -> str:
        return f"{self.method} {self.path}"

    def path_params(self) -> list[Param]:
        return [p for p in self.params if p.location == "path"]


@dataclass(slots=True)
class ApiSpec:
    title: str
    version: str
    spec_version: str
    servers: list[str]
    base_path: str
    operations: list[Operation]
    security_schemes: list[str] = field(default_factory=list)
    resolver: Any = None

    def sample(self, schema: dict[str, Any]) -> Any:
        return sample_value(schema, self.resolver or (lambda node: node))


def looks_like_spec(text: str) -> bool:
    head = text[:2000].lower()
    return '"openapi"' in head or '"swagger"' in head or "openapi:" in head or "swagger:" in head


def parse_spec(text: str, source: str = "specification") -> ApiSpec:
    if len(text.encode("utf-8", errors="ignore")) > MAX_SPEC_BYTES:
        raise SpecError("The specification is larger than the 5 MB limit.")
    try:
        document = json.loads(text)
    except ValueError:
        try:
            import yaml  # optional dependency: securerelease-cli[api]
        except ImportError as exc:
            raise SpecError(
                f"{source} is not JSON. Install PyYAML (pip install 'securerelease-cli[api]') to read YAML specifications."
            ) from exc
        try:
            document = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise SpecError(f"{source} is not valid JSON or YAML.") from exc
    if not isinstance(document, dict) or not ("openapi" in document or "swagger" in document):
        raise SpecError(f"{source} is not an OpenAPI or Swagger document.")
    if not isinstance(document.get("paths"), dict):
        raise SpecError(f"{source} does not define any paths.")
    return _build(document)


def _build(doc: dict[str, Any]) -> ApiSpec:
    def resolve(node: Any, _depth: int = 0) -> Any:
        while isinstance(node, dict) and isinstance(node.get("$ref"), str) and _depth < 20:
            ref = node["$ref"]
            if not ref.startswith("#/"):
                return {}
            target: Any = doc
            for part in ref[2:].split("/"):
                part = part.replace("~1", "/").replace("~0", "~")
                if not isinstance(target, dict) or part not in target:
                    return {}
                target = target[part]
            node, _depth = target, _depth + 1
        return node if isinstance(node, dict) else {}

    is_v2 = "swagger" in doc
    info = doc.get("info") if isinstance(doc.get("info"), dict) else {}
    global_security = doc.get("security")
    servers: list[str] = []
    if is_v2:
        host = doc.get("host", "")
        base_path = str(doc.get("basePath", "") or "")
        for scheme in doc.get("schemes", []) or []:
            servers.append(f"{scheme}://{host}{base_path}")
    else:
        for server in doc.get("servers", []) or []:
            if isinstance(server, dict) and isinstance(server.get("url"), str):
                servers.append(server["url"])
        base_path = urlparse(servers[0]).path if servers else ""
    base_path = base_path.rstrip("/")

    schemes_node = doc.get("securityDefinitions") if is_v2 else (doc.get("components") or {}).get("securitySchemes")
    schemes = sorted(schemes_node) if isinstance(schemes_node, dict) else []

    operations: list[Operation] = []
    for path, item in doc["paths"].items():
        item = resolve(item)
        shared = [p for p in (item.get("parameters") or [])]
        for method in HTTP_METHODS:
            raw = item.get(method)
            if not isinstance(raw, dict):
                continue
            merged: dict[tuple[str, str], Param] = {}
            body_schema = None
            for raw_param in shared + list(raw.get("parameters") or []):
                param = resolve(raw_param)
                if not param.get("name") or not param.get("in"):
                    continue
                if param["in"] == "body":
                    body_schema = resolve(param.get("schema"))
                    continue
                schema = resolve(param.get("schema")) if "schema" in param else {
                    k: v for k, v in param.items() if k in {"type", "format", "enum", "default", "items", "example", "minimum"}
                }
                location = str(param["in"])
                merged[(str(param["name"]), location)] = Param(
                    str(param["name"]), location, bool(param.get("required") or location == "path"), schema,
                )
            if not is_v2:
                content = resolve(raw.get("requestBody")).get("content") or {}
                media = content.get("application/json") or next(iter(content.values()), None)
                if isinstance(media, dict):
                    body_schema = resolve(media.get("schema"))
            security = raw["security"] if "security" in raw else global_security
            secured = bool(security) and not any(isinstance(req, dict) and not req for req in security)
            operations.append(Operation(
                method=method.upper(), path=str(path), operation_id=str(raw.get("operationId") or ""),
                params=list(merged.values()), secured=secured, deprecated=bool(raw.get("deprecated")),
                body_schema=body_schema, responses=[str(code) for code in (raw.get("responses") or {})],
            ))
    return ApiSpec(
        title=str(info.get("title", "")), version=str(info.get("version", "")),
        spec_version=str(doc.get("openapi") or doc.get("swagger")), servers=servers,
        base_path=base_path, operations=operations, security_schemes=schemes, resolver=resolve,
    )


def sample_value(schema: dict[str, Any], resolve: Any, depth: int = 0) -> Any:
    schema = resolve(schema)
    if depth > 6 or not schema:
        return "test"
    for key in ("example", "default"):
        if key in schema:
            return schema[key]
    if schema.get("enum"):
        return schema["enum"][0]
    for combo in ("allOf",):
        if schema.get(combo):
            merged: dict[str, Any] = {}
            for part in schema[combo]:
                value = sample_value(part, resolve, depth + 1)
                if isinstance(value, dict):
                    merged.update(value)
            return merged
    for combo in ("oneOf", "anyOf"):
        if schema.get(combo):
            return sample_value(schema[combo][0], resolve, depth + 1)
    kind, fmt = schema.get("type"), schema.get("format", "")
    if kind == "integer":
        return max(1, int(schema.get("minimum", 1)))
    if kind == "number":
        return float(max(1, schema.get("minimum", 1)))
    if kind == "boolean":
        return True
    if kind == "array":
        return [sample_value(schema.get("items", {}), resolve, depth + 1)]
    if kind == "object" or "properties" in schema:
        props = schema.get("properties") or {}
        return {name: sample_value(sub, resolve, depth + 1) for name, sub in list(props.items())[:10]}
    return {
        "uuid": "00000000-0000-4000-8000-000000000001", "date": "2024-01-01",
        "date-time": "2024-01-01T00:00:00Z", "email": "test@example.com", "uri": "https://example.com",
    }.get(fmt, "test")
