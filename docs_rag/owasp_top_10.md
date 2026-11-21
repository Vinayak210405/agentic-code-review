# Institutional Security Standard: OWASP Top 10 (2021)

Every pull request is screened against these rules before deployment. Rule IDs (SEC-xx) are cited in review comments.

## A01:2021 Broken Access Control
- SEC-01: Every HTTP route that reads or changes non-public data must be protected by the `@require_auth` decorator (Flask) or `Depends(get_current_user)` (FastAPI). Missing authorization on a route handler is a blocking finding.
- SEC-02: Perform object-level permission checks (the record must belong to the caller's tenant or user) before returning or mutating it. Never trust an id from the URL alone.
- SEC-03: File paths built from user input must be resolved and confined to an allowed base directory to prevent path traversal (`../`). Use `werkzeug.utils.secure_filename`.
- SEC-04: Redirect targets taken from query parameters (`next`, `return_to`) must be relative paths or match an allow-list of hosts to prevent open redirects.

## A02:2021 Cryptographic Failures
- SEC-05: MD5 and SHA-1 are banned for security purposes. Use SHA-256 or stronger. Passwords must be hashed with bcrypt, scrypt or argon2 — never a fast hash.
- SEC-06: Tokens, password-reset codes, OTPs, nonces and session ids must come from the `secrets` module. The `random` module (Mersenne Twister) is predictable and is not allowed for security values.
- SEC-07: Use authenticated encryption (AES-GCM, ChaCha20-Poly1305). DES, RC4, Blowfish and ECB mode are prohibited.
- SEC-08: All external traffic uses TLS (https://). Cleartext http is only acceptable for localhost.

## A03:2021 Injection
- SEC-09: SQL must be parameterised: `cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))`. Building SQL with f-strings, `+` concatenation, `%` formatting or `.format()` is a critical, blocking finding.
- SEC-10: Never pass untrusted input to `os.system`, `os.popen` or `subprocess` with `shell=True`. Use an argument list with `shell=False`.
- SEC-11: `eval`, `exec` and `compile` on dynamic input are prohibited. Use `ast.literal_eval` or `json.loads` for data.
- SEC-12: HTML must be rendered with auto-escaping templates. Do not wrap user content in `Markup`, `mark_safe` or `render_template_string`; in JavaScript use `textContent` instead of `innerHTML`.

## A04:2021 Insecure Design
- SEC-13: Prices, discounts, balances and roles must be computed server-side from authoritative data. Never trust values such as `price` or `is_admin` sent by the client.
- SEC-14: Security checks must not rely on `assert`, which is removed when Python runs with optimisation (-O). Raise `PermissionError` or `HTTPException(status_code=403)`.
- SEC-15: Outbound HTTP calls must set a timeout to avoid resource exhaustion.

## A05:2021 Security Misconfiguration
- SEC-16: Debug mode (`debug=True`, `DEBUG = True`) must never be enabled in committed configuration.
- SEC-17: CORS must list explicit trusted origins. A wildcard `*` origin combined with credentials is a blocking finding.
- SEC-18: Parse untrusted XML with `defusedxml` to prevent XXE and entity-expansion attacks.
- SEC-19: `.env` files and other local configuration with secrets must not be committed; commit `.env.example` with placeholders.

## A06:2021 Vulnerable and Outdated Components
- SEC-20: Pin every dependency to an exact version in requirements files and upgrade any package with a known CVE before release. Dependabot alerts must be resolved within 14 days for HIGH/CRITICAL advisories.

## A07:2021 Identification and Authentication Failures
- SEC-21: Credentials, API keys and tokens must never be hard-coded. Load them from environment variables or the secret manager, and rotate any key that reaches git history.
- SEC-22: JWTs must be verified with a pinned algorithm list (`algorithms=["HS256"]`). Disabling signature verification or accepting `alg: none` is critical.
- SEC-23: TLS certificate verification (`verify=True`) must stay enabled for all HTTP clients.
- SEC-24: Compare password hashes with constant-time library functions (`bcrypt.checkpw`, `hmac.compare_digest`); never compare plaintext passwords with `==`.

## A08:2021 Software and Data Integrity Failures
- SEC-25: Do not deserialize untrusted data with `pickle`, `marshal`, `dill`, `joblib` or `yaml.load`. Use JSON with schema validation or `yaml.safe_load`. Load ML checkpoints with `torch.load(..., weights_only=True)` or safetensors.
- SEC-26: Never pipe remote scripts into a shell (`curl | sh`) in Dockerfiles or CI; verify checksums of downloaded artefacts.

## A09:2021 Security Logging and Monitoring Failures
- SEC-27: Never log passwords, tokens, API keys or card numbers. Log a redacted identifier instead.
- SEC-28: Exceptions must not be silently swallowed (`except: pass`). Log them with `logger.exception` so security events reach monitoring.

## A10:2021 Server-Side Request Forgery (SSRF)
- SEC-29: Outbound requests to URLs supplied by users (webhooks, image fetchers, URL previews) must validate the scheme and host against an allow-list and block private, loopback and link-local address ranges (169.254.169.254 cloud metadata).
