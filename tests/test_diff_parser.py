from src.analysis.diff_parser import build_analysis_unit, detect_language, parse_patch
from src.analysis.git_diff import split_git_diff
from tests.conftest import SQLI_PATCH


def test_added_lines_get_real_new_file_line_numbers():
    parsed = parse_patch(SQLI_PATCH)
    assert sorted(parsed.added) == [16, 17]
    assert "SELECT" in parsed.added[16]


def test_removed_lines_do_not_advance_new_line_counter():
    patch = "@@ -10,3 +10,3 @@\n context\n-old_line()\n+new_line()\n tail\n"
    parsed = parse_patch(patch)
    assert parsed.added == {11: "new_line()"}
    assert parsed.removed_count == 1


def test_multiple_hunks():
    patch = "@@ -1,1 +1,2 @@\n a = 1\n+b = 2\n@@ -40,1 +41,2 @@\n x = 1\n+y = 2\n"
    assert sorted(parse_patch(patch).added) == [2, 42]


def test_fragment_inside_function_is_dedented_and_parsed():
    unit = build_analysis_unit("svc.py", SQLI_PATCH)
    assert unit.tree is not None
    assert unit.real_line(2) == 16  # line 2 of rebuilt source is PR line 16


def test_dangling_block_header_is_repaired():
    patch = "@@ -5,1 +5,2 @@\n x = 1\n+for item in items:\n"
    unit = build_analysis_unit("loop.py", patch)
    assert unit.tree is not None


def test_full_content_reports_only_changed_lines():
    content = "a = 1\nb = 2\nc = 3\n"
    unit = build_analysis_unit("m.py", "@@ -1,2 +1,3 @@\n a = 1\n+b = 2\n c = 3\n", content)
    assert unit.full_file and unit.changed_lines == {2}


def test_language_detection():
    assert detect_language("requirements.txt") == "requirements"
    assert detect_language("Dockerfile") == "dockerfile"
    assert detect_language("web/app.ts") == "typescript"
    assert detect_language(".env") == "dotenv"


def test_split_git_diff():
    diff = (
        "diff --git a/app.py b/app.py\nindex 1..2 100644\n--- a/app.py\n+++ b/app.py\n"
        "@@ -1,1 +1,2 @@\n x = 1\n+y = 2\n"
        "diff --git a/new.py b/new.py\nnew file mode 100644\n--- /dev/null\n+++ b/new.py\n"
        "@@ -0,0 +1,1 @@\n+print('hi')\n"
    )
    files = split_git_diff(diff)
    assert [f["filename"] for f in files] == ["app.py", "new.py"]
    assert files[1]["status"] == "added"
    assert files[0]["patch"].startswith("@@")
