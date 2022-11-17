# What is this?

This is an HTTP proxy that logs users in via OpenID Connect (OIDC) and only lets in users from a list of identities. It automatically reloads that list when it changes.

It was made to be used in Kubernetes, with the list mounted from a ConfigMap.
