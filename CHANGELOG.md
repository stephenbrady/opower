# Changelog

## 0.19.0 - 2026-07-23

### Added

- Add structured authentication and API failure details with safe HTTP metadata,
  correlation IDs, failure stages, and retry dispositions.
- Add request-aware HTTP classification. Eligible `401` responses can trigger one
  reauthentication, while generic `403` responses remain authorization failures.
- Add typed ConEd login and MFA response models for observed provider fields,
  including password-expiration, wait-time, device, MFA, and redirect state.
- Add one bounded, single-flight authentication manager per `Opower` instance
  with progress reporting, coherent invalidation, explicit reset, and
  utility-configurable transaction timeouts.
- Add fresh-request replay for authenticated GET and GraphQL POST operations.
  Replayed requests reconstruct tokens, customer scope, DSS selected entities,
  parameters, and URLs from current state.
- Add managed ConEd TOTP rollover handling so concurrent callers share one wait
  and one fresh-code retry.

### Changed

- Keep new retryable MFA, protocol, timeout, and reset failures compatible with
  existing consumers that catch `CannotConnect`.
- Preserve existing DSS DataBrowser `403` fallback behavior without starting a
  new login.
- Stop logging full successful response bodies and avoid exposing raw provider
  bodies through new failure metadata.
- Run the test workflow on Python `3.11`, `3.12`, `3.13`, and `3.14`.

### Compatibility

- Authentication coordination is scoped to one `Opower` instance. Callers
  should reuse one runtime instance per configured account.
- `ApiException.response_text` remains available for compatibility but is
  deprecated in favor of the sanitized `response_summary`.
