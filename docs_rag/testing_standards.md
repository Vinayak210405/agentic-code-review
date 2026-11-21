# Institutional Testing Standards

- TST-01: Every new or modified public function requires at least one PyTest unit test covering the happy path.
- TST-02: Functions that raise exceptions need a test using `pytest.raises` for each documented error condition.
- TST-03: Include boundary-value tests (0, negative numbers, empty strings, empty collections, None) for input-validating functions.
- TST-04: External dependencies (databases, HTTP clients, queues) must be replaced with `unittest.mock` objects or fixtures; unit tests must not touch the network.
- TST-05: Test files live in `tests/` and are named `test_<module>.py`; test functions are named `test_<function>_<scenario>`.
- TST-06: Pull requests must not reduce line coverage of the touched modules below 80%.
