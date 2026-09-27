"""Protocol-neutral templates: the schema the per-protocol adapters translate from."""

from __future__ import annotations

from typing import Any

from canarywire.runner.jsonpath import JSON_NODE

DEFAULT_MODEL = "canarywire-test"
ROLES = ("user", "assistant", "tool")
REQUEST_KEYS = frozenset({"model", "system", "tools", "messages"})
RESPONSE_KEYS = frozenset({"content", "tool_calls"})
TOOL_KEYS = frozenset({"name", "description", "parameters"})
CALL_KEYS = frozenset({"id", "name", "arguments"})
MESSAGE_KEYS = {
    "user": frozenset({"role", "content"}),
    "assistant": frozenset({"role", "content", "tool_calls"}),
    "tool": frozenset({"role", "tool_call_id", "content"}),
}


class TemplateError(ValueError):
    """A template is malformed; the message starts with its key path.

    Defined here, below the catalog, so both the catalog and this module can raise it;
    `canarywire.runner.catalog.TemplateError` is the same class.
    """


def check_neutral(request: Any, response: Any, where: str) -> None:
    """Validate a neutral template's request and response; `where` is `templates.<name>`."""
    _reject_json_nodes(request, f"{where}.request")
    _reject_json_nodes(response, f"{where}.response")
    _check_request(request, f"{where}.request")
    _check_response(response, f"{where}.response")


def _reject_json_nodes(doc: Any, where: str) -> None:
    if isinstance(doc, list):
        for index, item in enumerate(doc):
            _reject_json_nodes(item, f"{where}[{index}]")
    elif isinstance(doc, dict):
        for key, value in doc.items():
            if key == JSON_NODE:
                raise TemplateError(f"{where}.{key}: $json is not allowed in a neutral template")
            _reject_json_nodes(value, f"{where}.{key}")


def _check_request(request: Any, where: str) -> None:
    _check_keys(request, REQUEST_KEYS, where)
    for key in ("model", "system"):
        if key in request and not isinstance(request[key], str):
            raise TemplateError(f"{where}.{key}: expected a string")
    if "tools" in request:
        for index, tool in enumerate(_list(request["tools"], f"{where}.tools")):
            _check_tool(tool, f"{where}.tools[{index}]")
    messages = request.get("messages")
    if not isinstance(messages, list) or not messages:
        raise TemplateError(f"{where}.messages: expected a non-empty list")
    for index, message in enumerate(messages):
        _check_message(message, f"{where}.messages[{index}]")


def _check_tool(tool: Any, where: str) -> None:
    _check_keys(tool, TOOL_KEYS, where)
    if not isinstance(tool.get("name"), str):
        raise TemplateError(f"{where}.name: expected a string")
    if "description" in tool and not isinstance(tool["description"], str):
        raise TemplateError(f"{where}.description: expected a string")
    if "parameters" in tool:
        if not isinstance(tool["parameters"], dict):
            raise TemplateError(f"{where}.parameters: expected a mapping")
        _check_json_value(tool["parameters"], f"{where}.parameters")


def _check_message(message: Any, where: str) -> None:
    if not isinstance(message, dict):
        raise TemplateError(f"{where}: expected a mapping")
    role = message.get("role")
    if role not in ROLES:
        raise TemplateError(f"{where}.role: expected one of {', '.join(ROLES)}")
    _check_keys(message, MESSAGE_KEYS[role], where)
    content = message.get("content")
    if role == "user":
        if not isinstance(content, str):
            raise TemplateError(f"{where}.content: expected a string")
    elif role == "assistant":
        if not _has_answer(message, where):
            raise TemplateError(f"{where}: an assistant message needs content or tool_calls")
    else:
        if not isinstance(message.get("tool_call_id"), str):
            raise TemplateError(f"{where}.tool_call_id: expected a string")
        if not isinstance(content, (str, dict)):
            raise TemplateError(f"{where}.content: expected a string or a mapping")
        _check_json_value(content, f"{where}.content")


def _check_response(response: Any, where: str) -> None:
    _check_keys(response, RESPONSE_KEYS, where)
    if not _has_answer(response, where):
        raise TemplateError(f"{where}: needs content or tool_calls")


def _has_answer(doc: dict[str, Any], where: str) -> bool:
    """Check `content` (string or null) and `tool_calls`; True if either is non-empty.

    An empty string counts as no content: Anthropic rejects an empty text block. A null
    `tool_calls` counts as absent.
    """
    content = doc.get("content")
    if content is not None and not isinstance(content, str):
        raise TemplateError(f"{where}.content: expected a string or null")
    raw_calls = doc.get("tool_calls")
    calls = [] if raw_calls is None else _list(raw_calls, f"{where}.tool_calls")
    for index, call in enumerate(calls):
        call_where = f"{where}.tool_calls[{index}]"
        _check_keys(call, CALL_KEYS, call_where)
        for key in ("id", "name"):
            if not isinstance(call.get(key), str):
                raise TemplateError(f"{call_where}.{key}: expected a string")
        if not isinstance(call.get("arguments"), dict):
            raise TemplateError(f"{call_where}.arguments: expected a mapping")
        _check_json_value(call["arguments"], f"{call_where}.arguments")
    return bool(content) or bool(calls)


def _check_json_value(value: Any, where: str) -> None:
    """Mappings with string keys, lists, and None/str/int/float/bool leaves only.

    YAML can produce dates, sets and non-string keys (`1:`, `yes:`); JSON cannot carry them.
    """
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise TemplateError(f"{where}: keys must be strings")
            _check_json_value(item, f"{where}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _check_json_value(item, f"{where}[{index}]")
    elif not (value is None or isinstance(value, (str, int, float, bool))):
        raise TemplateError(f"{where}: expected a JSON value")


def _check_keys(doc: Any, allowed: frozenset[str], where: str) -> None:
    if not isinstance(doc, dict):
        raise TemplateError(f"{where}: expected a mapping")
    for key in doc:
        if key not in allowed:
            raise TemplateError(f"{where}.{key}: unknown key")


def _list(value: Any, where: str) -> list[Any]:
    if not isinstance(value, list):
        raise TemplateError(f"{where}: expected a list")
    return value
