# auth-template - Readme

## Provider Request Safety

Provider adapters can opt in to bounded requests by calling `requestProviderJson` with the configured `requestTimeoutMs` (default: 10,000 ms), and validate decoded responses with `validateTokenResponse` and `validateProviderUser`. The request and response-classification helpers report expected credential rejections as `ProviderAuthenticationRejectedError`; malformed responses, timeouts, and other provider failures remain operational errors. These protections apply only to adapters that adopt the helpers; this change does not update existing adapters.

Existing adapters can use the exported `throwProviderResponseError` helper to classify HTTP response failures without adopting the request helper.

`requestProviderJson` preserves a caller-provided `options.signal` alongside its timeout signal. Either cancellation source aborts the request.

Provider-facing error messages omit response bodies and transport details. Their `cause` is retained for trusted server-side diagnostics and should not be returned to clients.

## SSO Callback State

Always generate state before redirecting to the identity provider and pass the callback's non-empty `state` value to `authenticate`. Missing, invalid, expired, or reused state is rejected before authorization-code exchange.

## Contributing & Development

See [contributing.md](docs/contributing/contributing.md) for information on how to develop or contribute to this project!
