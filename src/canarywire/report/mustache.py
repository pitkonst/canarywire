"""A strict subset of Mustache: variables, sections, inverted sections, comments.

Strict: a name that resolves nowhere is an error, never an empty string. At render time a
later dotted part on a null value is null (`{{a.b}}` with `a` null renders empty). Standalone
section and comment tags follow the spec's whitespace rule. Partials, set delimiters, lambdas and
blocks are not supported.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

XML = {"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}
STANDALONE = frozenset("#^/!")
UNSUPPORTED = frozenset(">=$<")
SIGILS = frozenset("#^/!&>=$<")
# Characters XML 1.0 does not allow: C0 controls other than tab/newline/return, surrogates,
# U+FFFE and U+FFFF. The xml escape replaces them with U+FFFD.
XML_INVALID = frozenset(
    [chr(code) for code in range(0x20) if chr(code) not in "\t\n\r"]
    + [chr(code) for code in range(0xD800, 0xE000)]
    + ["\ufffe", "\uffff"]
)


class TemplateError(Exception):
    """A parse or render error, located by template name and 1-based line."""

    def __init__(self, name: str, line: int, message: str) -> None:
        """Keep the parts; str() is `name:line: message`."""
        super().__init__(f"{name}:{line}: {message}")
        self.name = name
        self.line = line
        self.message = message


@dataclass(frozen=True)
class Var:
    """`{{name}}` (escaped) or `{{{name}}}` / `{{& name}}` (raw)."""

    name: str
    raw: bool
    line: int


@dataclass(frozen=True)
class Section:
    """`{{#name}}…{{/name}}` or, inverted, `{{^name}}…{{/name}}`."""

    name: str
    inverted: bool
    body: tuple[Node, ...]
    line: int


Node = str | Var | Section


@dataclass(frozen=True)
class Template:
    """A parsed template."""

    name: str
    nodes: tuple[Node, ...]

    def render(self, context: Any, escape: str = "none") -> str:
        """Render against `context`; `escape` is `xml` or `none`."""
        out: list[str] = []
        self._render(self.nodes, [context], escape, out)
        return "".join(out)

    def check(self, shape: Any) -> None:
        """Resolve every name against `shape`, walking both branches of every section."""
        self._check(self.nodes, [shape])

    def _render(
        self, nodes: tuple[Node, ...], stack: list[Any], escape: str, out: list[str]
    ) -> None:
        for node in nodes:
            if isinstance(node, str):
                out.append(node)
            elif isinstance(node, Var):
                self._render_var(node, stack, escape, out)
            else:
                self._render_section(node, stack, escape, out)

    def _render_var(self, node: Var, stack: list[Any], escape: str, out: list[str]) -> None:
        text = self._scalar(self._lookup(node.name, stack, node.line, null_ok=True), node)
        if node.raw or escape != "xml":
            out.append(text)
        else:
            out.append("".join(_xml_char(char) for char in text))

    def _render_section(self, node: Section, stack: list[Any], escape: str, out: list[str]) -> None:
        value = self._lookup(node.name, stack, node.line, null_ok=True)
        if node.inverted:
            if _falsy(value):
                self._render(node.body, stack, escape, out)
        elif isinstance(value, list):
            for item in value:
                self._render(node.body, [*stack, item], escape, out)
        elif not _falsy(value):
            self._render(node.body, [*stack, value], escape, out)

    def _check(self, nodes: tuple[Node, ...], stack: list[Any]) -> None:
        for node in nodes:
            if isinstance(node, Var):
                self._scalar(self._lookup(node.name, stack, node.line), node)
            elif isinstance(node, Section):
                self._check_section(node, stack)

    def _check_section(self, node: Section, stack: list[Any]) -> None:
        value = self._lookup(node.name, stack, node.line)
        if node.inverted:
            self._check(node.body, stack)
        elif isinstance(value, list):
            if not value:
                raise TemplateError(
                    self.name, node.line, f'shape has an empty list at "{node.name}"'
                )
            self._check(node.body, [*stack, value[0]])
        else:
            self._check(node.body, [*stack, value])

    def _lookup(self, name: str, stack: list[Any], line: int, *, null_ok: bool = False) -> Any:
        """Resolve `name`; with `null_ok`, a later dotted part on a null value is null."""
        if name == ".":
            return stack[-1]
        first, *rest = name.split(".")
        for frame in reversed(stack):
            if isinstance(frame, dict) and first in frame:
                value = frame[first]
                break
        else:
            raise TemplateError(self.name, line, f'unknown name "{name}"')
        for part in rest:
            if value is None and null_ok:
                return None
            if not isinstance(value, dict) or part not in value:
                raise TemplateError(self.name, line, f'unknown name "{name}"')
            value = value[part]
        return value

    def _scalar(self, value: Any, node: Var) -> str:
        if value is None:
            return ""
        if isinstance(value, bool):
            return "true" if value else "false"
        if isinstance(value, float):
            return repr(value)
        if isinstance(value, (str, int)):
            return str(value)
        raise TemplateError(self.name, node.line, f'"{node.name}" is not a scalar')


def _xml_char(char: str) -> str:
    """Escape one character for XML; one not allowed in XML 1.0 becomes U+FFFD."""
    if char in XML_INVALID:
        return "\ufffd"
    return XML.get(char, char)


def _falsy(value: Any) -> bool:
    return value is None or value is False or value in ("", [])


@dataclass(frozen=True)
class _Tag:
    """One `{{...}}` tag as read from the source, with its trim boundaries."""

    sigil: str
    key: str
    line: int
    text_end: int
    resume: int


def _read_tag(source: str, name: str, pos: int, start: int) -> _Tag:
    """Parse the tag at `start`, applying the standalone-line whitespace trim."""
    line = source.count("\n", 0, start) + 1
    triple = source.startswith("{{{", start)
    close = "}}}" if triple else "}}"
    open_len = 3 if triple else 2
    end = source.find(close, start + open_len)
    if end == -1:
        raise TemplateError(name, line, "unclosed tag")
    inner = source[start + open_len : end].strip()
    end += len(close)
    sigil = "&" if triple else (inner[:1] if inner[:1] in SIGILS else "")
    key = inner if triple else inner[len(sigil) :].strip()
    if sigil in UNSUPPORTED:
        raise TemplateError(name, line, f"unsupported tag {{{{{inner}}}}}")
    if not key and sigil != "!":
        raise TemplateError(name, line, "empty tag")
    text_end, resume = start, end
    if sigil in STANDALONE:
        text_end, resume = _standalone_trim(source, pos, start, end) or (start, end)
    return _Tag(sigil, key, line, text_end, resume)


def _standalone_trim(source: str, pos: int, start: int, end: int) -> tuple[int, int] | None:
    """If the tag is alone on its line, the line boundaries to trim; else None."""
    line_start = source.rfind("\n", 0, start) + 1
    newline = source.find("\n", end)
    line_end = len(source) if newline == -1 else newline + 1
    tail_end = len(source) if newline == -1 else newline
    tail = source[end:tail_end].rstrip("\r")
    before_ok = line_start >= pos and not source[line_start:start].strip(" \t")
    if before_ok and not tail.strip(" \t"):
        return line_start, line_end
    return None


def parse(source: str, name: str) -> Template:
    """Parse `source`; errors name the template and line."""
    root: list[Node] = []
    stack: list[tuple[str, int, list[Node], bool]] = []  # name, line, parent, inverted
    current = root
    pos = 0
    while True:
        start = source.find("{{", pos)
        if start == -1:
            current.append(source[pos:])
            break
        tag = _read_tag(source, name, pos, start)
        current.append(source[pos : tag.text_end])
        pos = tag.resume
        if tag.sigil == "!":
            continue
        if tag.sigil and tag.sigil in "#^":
            stack.append((tag.key, tag.line, current, tag.sigil == "^"))
            current = []
        elif tag.sigil == "/":
            current = _close_section(name, tag, stack, current)
        else:
            current.append(Var(tag.key, tag.sigil == "&", tag.line))
    if stack:
        open_name, open_line, _, _ = stack[-1]
        raise TemplateError(name, open_line, f'unclosed section "{open_name}"')
    return Template(name, tuple(n for n in root if n != ""))


def _close_section(
    name: str,
    tag: _Tag,
    stack: list[tuple[str, int, list[Node], bool]],
    current: list[Node],
) -> list[Node]:
    """Pop the matching open section, append it (with `current` as its body) to its parent."""
    if not stack:
        raise TemplateError(name, tag.line, f'unexpected close "{tag.key}"')
    open_name, open_line, parent, inverted = stack.pop()
    if open_name != tag.key:
        message = f'mismatched close "{tag.key}", expected "{open_name}"'
        raise TemplateError(name, tag.line, message)
    body = tuple(n for n in current if n != "")
    parent.append(Section(tag.key, inverted, body, open_line))
    return parent
