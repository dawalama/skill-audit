"""Tests for executable source projection."""

from skill_audit.code_projection import executable_text, project_code


def test_python_projection_drops_comments_and_docstrings():
    source = '''"""Mentions ~/.aws/credentials in docs."""
# ~/.aws/credentials in a comment
print(config)
'''

    projected = executable_text(project_code(source, filename="tool.py"))

    assert "~/.aws/credentials" not in projected
    assert "print(config)" in projected


def test_python_projection_sanitizes_literal_log_strings():
    source = 'print("Skipping: file is not natural language (code/config)")\nprint(config)\n'

    projected = executable_text(project_code(source, filename="tool.py"))

    assert "code/config" not in projected
    assert "print('<str>')" in projected
    assert "print(config)" in projected


def test_python_projection_keeps_code_inside_documented_functions():
    source = '''def audit():
    """Mentions ~/.aws/credentials in docs."""
    print(config)
'''

    projected = executable_text(project_code(source, filename="tool.py"))

    assert "~/.aws/credentials" not in projected
    assert "print(config)" in projected


def test_shell_projection_drops_comments_but_preserves_quoted_hashes():
    source = "echo '# not comment'\n# cat ~/.aws/credentials\ncat ~/.aws/credentials\n"

    projected = executable_text(project_code(source, filename="install.sh"))

    assert "echo '# not comment'" in projected
    assert "# cat" not in projected
    assert "cat ~/.aws/credentials" in projected


def test_javascript_projection_drops_comments_but_preserves_code():
    source = """// ~/.aws/credentials
console.log("Skipping config");
console.log(config);
"""

    projected = executable_text(project_code(source, filename="tool.js"))

    assert "~/.aws/credentials" not in projected
    assert 'console.log("Skipping config");' in projected
    assert "console.log(config);" in projected
