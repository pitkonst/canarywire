r"""Generate strings from a JSON Schema `pattern`: the ECMA-262 subset shared with Python.

Supported: literals and escapes, classes and ranges (also negated), `\d \w \s` and their
negations (ASCII), `.` (printable ASCII), quantifiers `? * + {n} {n,} {n,m}` (open-ended
repeats capped at 8; a lazy `?` suffix is accepted), groups, alternation, and `^`/`$` at the
ends of the pattern. Everything else is rejected with an error naming the construct.
"""

from __future__ import annotations

import re
import string
from dataclasses import dataclass
from typing import TYPE_CHECKING, NoReturn, TypeAlias

from canarywire.values.errors import CanaryTypeError

if TYPE_CHECKING:
    import random

OPEN_REPEAT = 8
ASCII_MAX = 0x7F
HEX2 = 2
HEX4 = 4
PRINTABLE = tuple(chr(code) for code in range(0x20, 0x7F))
DIGITS = tuple(string.digits)
WORD = tuple(sorted(string.ascii_letters + string.digits + "_"))
SPACE = (" ", "\t", "\n", "\r", "\f", "\v")
CLASS_ESCAPES = {
    "d": DIGITS,
    "D": tuple(c for c in PRINTABLE if c not in DIGITS),
    "w": WORD,
    "W": tuple(c for c in PRINTABLE if c not in WORD),
    "s": SPACE,
    "S": tuple(c for c in PRINTABLE if c not in SPACE),
}
CONTROL_ESCAPES = {"t": "\t", "n": "\n", "r": "\r", "f": "\f", "v": "\v"}
UNSUPPORTED_ESCAPES = {
    "b": "word boundary",
    "B": "word boundary",
    "k": "named backreference",
    "p": "Unicode property escape",
    "P": "Unicode property escape",
    "c": "control escape",
}
GROUP_KINDS = (
    ("?=", "lookahead"),
    ("?!", "lookahead"),
    ("?<=", "lookbehind"),
    ("?<!", "lookbehind"),
    ("?<", "named group"),
    ("?P", "named group"),
)
BRACES = re.compile(r"\{(\d+)(,(\d*))?\}")


class PatternError(CanaryTypeError):
    """A pattern uses an unsupported construct or cannot be generated from."""


@dataclass(frozen=True)
class Chars:
    """One character out of `options`."""

    options: tuple[str, ...]


@dataclass(frozen=True)
class Seq:
    """Items one after another."""

    items: tuple[Node, ...]


@dataclass(frozen=True)
class Alt:
    """One of the options."""

    options: tuple[Node, ...]


@dataclass(frozen=True)
class Repeat:
    """`node` repeated between `low` and `high` times."""

    node: Node
    low: int
    high: int


Node: TypeAlias = "Chars | Seq | Alt | Repeat"


class PatternGenerator:
    """A seeded generator for one pattern; construction validates the pattern."""

    def __init__(self, pattern: str) -> None:
        """Parse `pattern`; raise PatternError if it is unsupported or invalid."""
        self.pattern = pattern
        self._tree = parse(pattern)
        try:
            self._check = re.compile(pattern, re.ASCII)
        except re.error as exc:
            raise PatternError(f"invalid pattern: {exc}") from exc

    def __call__(self, rng: random.Random) -> str:
        """Generate one value, checked against the pattern."""
        value = generate(self._tree, rng)
        if self._check.fullmatch(value) is None:
            raise PatternError(f"generated {value!r} does not match the pattern")
        return value


def parse(pattern: str) -> Node:
    """Parse a pattern into a generation tree."""
    return _Parser(pattern).parse()


def generate(node: Node, rng: random.Random) -> str:
    """Generate one string from a tree."""
    if isinstance(node, Chars):
        return rng.choice(node.options)
    if isinstance(node, Seq):
        return "".join(generate(item, rng) for item in node.items)
    if isinstance(node, Alt):
        return generate(rng.choice(node.options), rng)
    return "".join(generate(node.node, rng) for _ in range(rng.randint(node.low, node.high)))


def _ends_with_anchor(pattern: str) -> bool:
    if not pattern.endswith("$"):
        return False
    body = pattern[:-1]
    backslashes = len(body) - len(body.rstrip("\\"))
    return backslashes % 2 == 0


class _Parser:
    def __init__(self, pattern: str) -> None:
        start = 1 if pattern.startswith("^") else 0
        end = len(pattern) - 1 if _ends_with_anchor(pattern) else len(pattern)
        self._text = pattern[start:end]
        self._offset = start
        self._i = 0

    def parse(self) -> Node:
        node = self._alternation()
        if self._i < len(self._text):
            self._fail(f"unexpected {self._text[self._i]!r}")
        return node

    def _peek(self) -> str | None:
        return self._text[self._i] if self._i < len(self._text) else None

    def _take(self) -> str:
        if self._i >= len(self._text):
            self._fail("unexpected end of pattern")
        char = self._text[self._i]
        self._i += 1
        return char

    def _fail(self, message: str) -> NoReturn:
        raise PatternError(f"{message} at position {self._i + self._offset}")

    def _alternation(self) -> Node:
        options = [self._sequence()]
        while self._peek() == "|":
            self._i += 1
            options.append(self._sequence())
        return options[0] if len(options) == 1 else Alt(tuple(options))

    def _sequence(self) -> Node:
        items: list[Node] = []
        while self._peek() not in (None, "|", ")"):
            items.append(self._quantified())
        return Seq(tuple(items))

    def _quantified(self) -> Node:
        atom = self._atom()
        bounds = self._quantifier()
        if bounds is None:
            return atom
        if self._peek() == "?":
            self._i += 1  # lazy: generates the same strings
        return Repeat(atom, *bounds)

    def _quantifier(self) -> tuple[int, int] | None:
        char = self._peek()
        if char in ("?", "*", "+"):
            self._i += 1
            return {"?": (0, 1), "*": (0, OPEN_REPEAT), "+": (1, OPEN_REPEAT)}[char]
        if char == "{":
            match = BRACES.match(self._text, self._i)
            if match is None:
                return None  # a literal "{"
            self._i = match.end()
            low = int(match.group(1))
            if match.group(2) is None:
                return (low, low)
            if not match.group(3):
                return (low, low + OPEN_REPEAT)
            high = int(match.group(3))
            if high < low:
                self._fail("quantifier range is out of order")
            return (low, high)
        return None

    def _atom(self) -> Node:
        char = self._take()
        if char == "(":
            return self._group()
        if char == "[":
            return self._class()
        if char == ".":
            return Chars(PRINTABLE)
        if char == "\\":
            return Chars(self._escape())
        if char in "*+?":
            self._fail("nothing to repeat")
        if char in "^$":
            self._fail("anchors are only supported at the start and end")
        return Chars((char,))

    def _group(self) -> Node:
        if self._text.startswith("?:", self._i):
            self._i += 2
        elif self._peek() == "?":
            rest = self._text[self._i :]
            kind = next((name for prefix, name in GROUP_KINDS if rest.startswith(prefix)), None)
            self._fail(f"{kind or 'inline flags'} is not supported")
        node = self._alternation()
        if self._peek() != ")":
            self._fail("unbalanced parenthesis")
        self._i += 1
        return node

    def _escape(self) -> tuple[str, ...]:
        char = self._take()
        if char in CLASS_ESCAPES:
            return CLASS_ESCAPES[char]
        if char in CONTROL_ESCAPES:
            return (CONTROL_ESCAPES[char],)
        if char in ("x", "u"):
            return (self._hex(HEX2 if char == "x" else HEX4),)
        if char.isdigit():
            self._fail("backreferences are not supported")
        if char in UNSUPPORTED_ESCAPES:
            self._fail(f"{UNSUPPORTED_ESCAPES[char]} is not supported")
        if char.isalnum():
            self._fail(f"escape \\{char} is not supported")
        return (char,)

    def _hex(self, width: int) -> str:
        digits = self._text[self._i : self._i + width]
        if len(digits) != width or any(c not in string.hexdigits for c in digits):
            self._fail("invalid hex escape")
        self._i += width
        code = int(digits, 16)
        if code > ASCII_MAX:
            self._fail("only ASCII characters are supported")
        return chr(code)

    def _class(self) -> Chars:
        negate = self._peek() == "^"
        if negate:
            self._i += 1
        if self._peek() == "]":
            self._fail("empty character class")
        chosen: set[str] = set()
        while True:
            char = self._take()
            if char == "]":
                break
            low = self._class_member(char)
            if isinstance(low, tuple):
                if self._peek() == "-" and self._text[self._i + 1 : self._i + 2] not in (
                    "",
                    "]",
                ):
                    self._fail("invalid character range")
                chosen.update(low)
                continue
            if self._peek() == "-" and self._text[self._i + 1 : self._i + 2] not in ("", "]"):
                self._i += 1
                high = self._class_member(self._take())
                if isinstance(high, tuple) or ord(high) < ord(low):
                    self._fail("invalid character range")
                chosen.update(chr(code) for code in range(ord(low), ord(high) + 1))
            else:
                chosen.add(low)
        options = [c for c in PRINTABLE if c not in chosen] if negate else sorted(chosen)
        if not options:
            self._fail("character class matches nothing")
        return Chars(tuple(options))

    def _class_member(self, char: str) -> str | tuple[str, ...]:
        if char != "\\":
            return char
        escaped = self._escape()
        return escaped if len(escaped) > 1 else escaped[0]
