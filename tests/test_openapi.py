import json

import pytest

from securerelease.scanners.openapi import SpecError, looks_like_spec, parse_spec, sample_value

SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "T", "version": "1"},
    "servers": [{"url": "https://api.example.test/v1"}],
    "security": [{"bearer": []}],
    "components": {
        "securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}},
        "schemas": {"Pet": {"type": "object", "properties": {"name": {"type": "string"}, "age": {"type": "integer"}}}},
        "parameters": {"Id": {"name": "id", "in": "path", "required": True, "schema": {"type": "string", "format": "uuid"}}},
    },
    "paths": {
        "/pets": {
            "get": {"responses": {"200": {"description": "ok"}}},
            "post": {"requestBody": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/Pet"}}}},
                     "responses": {"201": {"description": "c"}}},
        },
        "/pets/{id}": {
            "parameters": [{"$ref": "#/components/parameters/Id"}],
            "get": {"security": [], "responses": {"200": {"description": "ok"}}},
        },
        "/optional": {"get": {"security": [{}], "responses": {}}},
    },
}


def test_operations_security_and_base_path():
    spec = parse_spec(json.dumps(SPEC))
    ops = {op.key: op for op in spec.operations}
    assert set(ops) == {"GET /pets", "POST /pets", "GET /pets/{id}", "GET /optional"}
    assert ops["GET /pets"].secured is True  # inherited from the global requirement
    assert ops["GET /pets/{id}"].secured is False  # explicit empty list overrides it
    assert ops["GET /optional"].secured is False  # an empty requirement object makes auth optional
    assert spec.base_path == "/v1"
    assert spec.security_schemes == ["bearer"]


def test_refs_are_resolved_and_samples_generated():
    spec = parse_spec(json.dumps(SPEC))
    ops = {op.key: op for op in spec.operations}
    param = ops["GET /pets/{id}"].path_params()[0]
    assert param.name == "id" and spec.sample(param.schema) == "00000000-0000-4000-8000-000000000001"
    assert spec.sample(ops["POST /pets"].body_schema) == {"name": "test", "age": 1}


def test_swagger2_is_supported():
    doc = {
        "swagger": "2.0", "info": {"title": "S", "version": "1"}, "host": "api.test", "basePath": "/v2", "schemes": ["https"],
        "securityDefinitions": {"key": {"type": "apiKey", "in": "header", "name": "X-Key"}},
        "paths": {"/a/{n}": {"get": {"security": [{"key": []}],
                                     "parameters": [{"name": "n", "in": "path", "required": True, "type": "integer"},
                                                    {"name": "b", "in": "body", "schema": {"type": "object"}}],
                                     "responses": {"200": {"description": "ok"}}}}},
    }
    spec = parse_spec(json.dumps(doc))
    op = spec.operations[0]
    assert spec.base_path == "/v2" and op.secured and spec.sample(op.path_params()[0].schema) == 1
    assert op.body_schema == {"type": "object"}


def test_cyclic_refs_do_not_hang():
    doc = {"openapi": "3.0.0", "info": {}, "paths": {"/x": {"get": {"parameters": [{"$ref": "#/components/parameters/A"}]}}},
           "components": {"parameters": {"A": {"$ref": "#/components/parameters/A"}}}}
    assert parse_spec(json.dumps(doc)).operations[0].params == []


def test_invalid_documents_are_rejected():
    with pytest.raises(SpecError):
        parse_spec('{"hello": "world"}')
    with pytest.raises(SpecError):
        parse_spec(json.dumps({"openapi": "3.0.0"}))


def test_yaml_requires_optional_dependency_or_parses():
    text = "openapi: 3.0.0\ninfo: {title: Y, version: '1'}\npaths:\n  /a:\n    get:\n      responses: {}\n"
    try:
        import yaml  # noqa: F401
    except ImportError:
        with pytest.raises(SpecError, match="PyYAML"):
            parse_spec(text)
    else:
        assert parse_spec(text).operations[0].key == "GET /a"


def test_looks_like_spec_and_sample_defaults():
    assert looks_like_spec('{"openapi": "3.0.0"}') and not looks_like_spec("<html></html>")
    assert sample_value({"type": "string", "enum": ["a", "b"]}, lambda n: n) == "a"
    assert sample_value({"type": "array", "items": {"type": "boolean"}}, lambda n: n) == [True]
