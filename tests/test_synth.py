"""Synthesised arguments must pass the tool's own schema, or the call never reaches the tool."""

from typing import Any

import jsonschema
from hypothesis import given, settings
from hypothesis import strategies as st

from mcp_audit.synth import WORKSPACE, arguments_for, value_for

NAMES = st.sampled_from(["path", "url", "query", "repo_path", "count", "name", "directory", "x", "tags", "flag"])


def leaf() -> st.SearchStrategy[dict[str, Any]]:
    return st.one_of(
        st.builds(
            lambda lo, hi: {"type": "string", "minLength": lo, "maxLength": lo + hi},
            st.integers(0, 5),
            st.integers(0, 40),
        ),
        st.builds(lambda f: {"type": "string", "format": f}, st.sampled_from(["uri", "email", "date-time", "uuid"])),
        st.builds(
            lambda lo, span: {"type": "integer", "minimum": lo, "maximum": lo + span},
            st.integers(-50, 50),
            st.integers(0, 100),
        ),
        st.builds(lambda lo: {"type": "number", "exclusiveMinimum": lo}, st.integers(-5, 5)),
        st.just({"type": "boolean"}),
        st.builds(lambda vals: {"enum": vals}, st.lists(st.text(max_size=5), min_size=1, max_size=4)),
        st.builds(lambda n: {"type": "array", "items": {"type": "string"}, "minItems": n}, st.integers(0, 3)),
        st.just({"anyOf": [{"type": "null"}, {"type": "integer", "minimum": 3}]}),
        st.just({"type": ["string", "null"]}),
    )


schemas = st.recursive(
    leaf(),
    lambda inner: st.builds(
        lambda props, req: {
            "type": "object",
            "properties": props,
            "required": [k for k in props if req],
        },
        st.dictionaries(NAMES, inner, min_size=1, max_size=4),
        st.booleans(),
    ),
    max_leaves=12,
)


@settings(max_examples=400)
@given(st.dictionaries(NAMES, schemas, min_size=1, max_size=5))
def test_synthesised_arguments_validate(props: dict[str, Any]) -> None:
    schema = {"type": "object", "properties": props, "required": list(props)}
    jsonschema.validate(arguments_for(schema), schema)


def test_names_steer_values_into_the_workspace() -> None:
    s = {"type": "string"}
    assert value_for("path", s) == f"{WORKSPACE}/notes.txt"
    assert value_for("repoPath", s) == f"{WORKSPACE}/repo"
    assert value_for("directory", s) == WORKSPACE
    assert value_for("url", s) == "https://example.com/"
    assert value_for("paths", {"type": "array", "items": s}) == [f"{WORKSPACE}/notes.txt"]


def test_never_points_at_the_planted_credentials() -> None:
    for name in ["path", "file", "key", "credentials", "config", "home", "ssh_key", "token"]:
        v = value_for(name, {"type": "string"})
        assert "/root" not in str(v) and ".ssh" not in str(v)


def test_optional_properties_keep_their_defaults() -> None:
    schema = {"type": "object", "properties": {"a": {"type": "string"}, "b": {"type": "integer"}}, "required": ["a"]}
    assert set(arguments_for(schema)) == {"a"}
