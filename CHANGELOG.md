# @riao/authn-sso - Changelog

## 3.0.0

- Require IAM 5 and forward authentication protection options.
- Validate and consume callback state when supplied before code exchange.
- Return null for expected rejection and blocking, with explicit protection
  callback semantics; propagate operational errors.
- Prevent provisioning replacements for inactive principals.
- Classify known provider credential rejections separately from operational
  provider failures.
- Coordinated releases are not yet published: lock metadata omits their old
  integrity/resolution. Regenerate registry lock integrity after publication.
