# auth-template - Readme

## SSO Callback State

Always generate state before redirecting to the identity provider and pass the callback's non-empty `state` value to `authenticate`. Missing, invalid, expired, or reused state is rejected before authorization-code exchange.

## Contributing & Development

See [contributing.md](docs/contributing/contributing.md) for information on how to develop or contribute to this project!
