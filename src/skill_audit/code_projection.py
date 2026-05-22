"""Project source files into executable text for trust scanning.

Markdown prose is an agent instruction surface and should be scanned as prose.
Direct scripts are different: comments, docstrings, and inert string literals
should not be treated as executable behavior. This module owns that boundary.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from typing import Literal


ChunkKind = Literal["code", "string", "comment", "doc"]


@dataclass(frozen=True)
class CodeChunk:
    kind: ChunkKind
    text: str
    line_start: int
    line_end: int
    executable: bool


def project_code(
    text: str,
    *,
    filename: str = "",
    language: str = "",
) -> list[CodeChunk]:
    """Project code into chunks that are safe for static trust scanning."""
    lang = _normalize_language(language=language, filename=filename)
    if lang == "python":
        return _project_python(text)
    if lang == "shell":
        return _project_line_language(text, comment_markers=("#",))
    if lang in {"javascript", "typescript"}:
        return _project_c_style_language(text)
    return [CodeChunk("code", text, 1, max(1, len(text.splitlines())), True)]


def executable_text(chunks: list[CodeChunk]) -> str:
    """Return text from executable chunks only."""
    return "\n".join(chunk.text for chunk in chunks if chunk.executable and chunk.text.strip())


def _normalize_language(*, language: str, filename: str) -> str:
    lang = language.lower().strip()
    suffix = filename.rsplit(".", 1)[-1].lower() if "." in filename else filename.lower()
    if lang in {"python", "py"} or suffix == "py":
        return "python"
    if lang in {"bash", "sh", "zsh", "fish", "shell"} or suffix in {"sh", "bash", "zsh", "fish"}:
        return "shell"
    if lang in {"javascript", "js", "node"} or suffix in {"js", "cjs", "mjs", "jsx"}:
        return "javascript"
    if lang in {"typescript", "ts"} or suffix in {"ts", "tsx"}:
        return "typescript"
    return lang or suffix


def _project_python(text: str) -> list[CodeChunk]:
    chunks: list[CodeChunk] = []
    chunks.extend(_python_comment_chunks(text))

    try:
        tree = ast.parse(text)
    except SyntaxError:
        return _project_line_language(text, comment_markers=("#",))

    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.Load, ast.Store, ast.Del, ast.Constant)):
            continue
        if isinstance(node, ast.Expr) and isinstance(getattr(node, "value", None), ast.Constant):
            value = node.value.value
            if isinstance(value, str):
                chunks.append(_chunk_from_node("doc", node, text=value, executable=False))
            continue
        if not isinstance(node, ast.stmt):
            continue
        if _is_compound_statement(node):
            continue
        try:
            rendered = ast.unparse(node)
        except Exception:
            continue
        chunks.append(_chunk_from_node("code", node, text=_sanitize_benign_log_strings(rendered), executable=True))

    return _dedupe_chunks(chunks)


def _python_comment_chunks(text: str) -> list[CodeChunk]:
    chunks = []
    for lineno, line in enumerate(text.splitlines(), 1):
        stripped = line.lstrip()
        if stripped.startswith("#"):
            chunks.append(CodeChunk("comment", stripped, lineno, lineno, False))
    return chunks


def _is_compound_statement(node: ast.AST) -> bool:
    return isinstance(
        node,
        (
            ast.FunctionDef,
            ast.AsyncFunctionDef,
            ast.ClassDef,
            ast.If,
            ast.For,
            ast.AsyncFor,
            ast.While,
            ast.With,
            ast.AsyncWith,
            ast.Try,
            ast.Match,
        ),
    )


def _chunk_from_node(
    kind: ChunkKind,
    node: ast.AST,
    *,
    text: str | None = None,
    executable: bool,
) -> CodeChunk:
    line_start = getattr(node, "lineno", 1) or 1
    line_end = getattr(node, "end_lineno", line_start) or line_start
    rendered = text if text is not None else ""
    return CodeChunk(kind, rendered, line_start, line_end, executable)


def _sanitize_benign_log_strings(code: str) -> str:
    """Replace pure string log messages so words like config don't look like objects."""
    log_call = re.match(r"^(print|logger\.(?:info|debug|warning|warn|error|exception))\((.*)\)$", code, re.DOTALL)
    if not log_call:
        return code
    args = log_call.group(2)
    if re.fullmatch(r"\s*([rubfRUBF]*)(['\"]).*\2\s*", args, re.DOTALL):
        return f"{log_call.group(1)}('<str>')"
    return code


def _project_line_language(text: str, *, comment_markers: tuple[str, ...]) -> list[CodeChunk]:
    chunks: list[CodeChunk] = []
    for lineno, line in enumerate(text.splitlines(), 1):
        stripped = line.lstrip()
        if any(stripped.startswith(marker) for marker in comment_markers):
            chunks.append(CodeChunk("comment", stripped, lineno, lineno, False))
            continue
        code = line
        for marker in comment_markers:
            code = _strip_comment_outside_quotes(code, marker)
        if code.strip():
            chunks.append(CodeChunk("code", code, lineno, lineno, True))
    return chunks


def _project_c_style_language(text: str) -> list[CodeChunk]:
    without_block_comments = re.sub(r"/\*.*?\*/", _block_comment_replacer, text, flags=re.DOTALL)
    return _project_line_language(without_block_comments, comment_markers=("//",))


def _block_comment_replacer(match: re.Match) -> str:
    line_count = match.group(0).count("\n")
    return "\n" * line_count


def _strip_comment_outside_quotes(line: str, marker: str) -> str:
    quote = ""
    escaped = False
    i = 0
    while i < len(line):
        ch = line[i]
        if escaped:
            escaped = False
        elif ch == "\\":
            escaped = True
        elif quote:
            if ch == quote:
                quote = ""
        elif ch in {"'", '"', "`"}:
            quote = ch
        elif line.startswith(marker, i):
            return line[:i].rstrip()
        i += 1
    return line


def _dedupe_chunks(chunks: list[CodeChunk]) -> list[CodeChunk]:
    seen: set[tuple[ChunkKind, str, int, int, bool]] = set()
    result: list[CodeChunk] = []
    for chunk in chunks:
        key = (chunk.kind, chunk.text, chunk.line_start, chunk.line_end, chunk.executable)
        if key in seen:
            continue
        seen.add(key)
        result.append(chunk)
    return result
