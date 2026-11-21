# Institutional Python Coding Standards

## Style (PEP 8)
- STD-01: Follow PEP 8. Functions and variables use snake_case, classes use CapWords, constants use UPPER_CASE.
- STD-02: Maximum line length is 120 characters.
- STD-03: Public functions and classes must have type hints for all parameters and the return value.

## Error Handling
- STD-04: Never use a bare `except:`. Catch the specific exceptions you can handle (for example `except ValueError`) so programming errors are not masked.
- STD-05: Do not use mutable default arguments (`def f(items=[])`); default to `None` and create the object inside the function.
- STD-06: Compare to None with `is None` / `is not None`, not `==`.

## Performance
- STD-07: Avoid N+1 query patterns: do not issue a database query inside a loop over records. Fetch related rows in bulk (`WHERE id IN (...)`, `select_related`, `prefetch_related`, joins) outside the loop.
- STD-08: Functions should stay under 50 lines and a cyclomatic complexity of 10; split larger functions into helpers.

## Logging
- STD-09: Use the `logging` module instead of `print()` in application code.
- STD-10: Do not shadow Python built-ins such as `list`, `dict`, `id`, `type`, `input` or `file` with variable names.

## Maintenance
- STD-11: TODO/FIXME comments must reference a ticket id (e.g. `# TODO(PROJ-123): ...`).
- STD-12: Remove unused imports and dead code before requesting review.
