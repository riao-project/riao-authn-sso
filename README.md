# @riao/authn-sso

Framework-neutral OAuth2/OIDC authentication base for provider drivers.

## Provider Request Safety

Provider adapters can opt in to bounded requests by calling `requestProviderJson` with the configured `requestTimeoutMs` (default: 10,000 ms), and validate decoded responses with `validateTokenResponse` and `validateProviderUser`. The request and response-classification helpers report expected credential rejections as `ProviderAuthenticationRejectedError`; malformed responses, timeouts, and other provider failures remain operational errors. These protections apply only to adapters that adopt the helpers; this change does not update existing adapters.

Existing adapters can use the exported `throwProviderResponseError` helper to classify HTTP response failures without adopting the request helper.

`requestProviderJson` preserves a caller-provided `options.signal` alongside its timeout signal. Either cancellation source aborts the request.

Provider-facing error messages omit response bodies and transport details. Their `cause` is retained for trusted server-side diagnostics and should not be returned to clients.

## SSO Callback State

Always generate state before redirecting to the identity provider. Store the returned `stateBinding` in a secure, HttpOnly cookie (SameSite=Lax for a query/GET callback; use SameSite=None; Secure for a cross-site POST callback) or another unguessable browser-session secret that survives the provider redirect. Pass that cookie value to `generateAuthorizationUrl` when reusing an existing browser binding, and pass the same value with the callback's `state` to `authenticate`. Do not use the callback's state, a user identifier, or another attacker-observable value as the binding. Missing, invalid, expired, reused, or browser-mismatched state is rejected before authorization-code exchange.

## Contributing & Development

See [contributing.md](docs/contributing/contributing.md) for information on how to develop or contribute to this project!
