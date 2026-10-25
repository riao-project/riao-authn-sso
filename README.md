# auth-template - Readme

## Provider Request Safety

SSO provider requests use a bounded timeout. Configure `requestTimeoutMs` on the authentication provider (default: 10,000 ms) to tune the limit. Token and user-info responses are validated before use. Expected credential rejections are reported as `ProviderAuthenticationRejectedError`; malformed responses, timeouts, and other provider failures remain operational errors.

Existing adapters can use the exported `throwProviderResponseError` helper to classify HTTP response failures without adopting the request helper.

Provider-facing error messages omit response bodies and transport details. Their `cause` is retained for trusted server-side diagnostics and should not be returned to clients.

## SSO Callback State

Always generate state before redirecting to the identity provider and pass the callback's non-empty `state` value to `authenticate`. Missing, invalid, expired, or reused state is rejected before authorization-code exchange.

## Contributing & Development

See [contributing.md](docs/contributing/contributing.md) for information on how to develop or contribute to this project!
