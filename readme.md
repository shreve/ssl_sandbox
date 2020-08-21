TLS Sandbox
===========

A simplified setup for testing Tapdance TLS forgery

* `client.go` is a client which connects to our TLS 1.3 decoy and dumps it's parameters
* `forge.c` takes crypto parameters and attempts to decrypt TLS packets
* `compat/` is all of OpenSSL's internal header files which allows forge.c to
  reach into opaque library objects
* `openssl/` is included as a submodule for introspection and to lock the version


## Problem

This was created to make a working example of forging a TLS 1.3 connection. That
is, beginning a connection between a client and one host, then resuming the
connection on another.

There is an example in the spec [1], [2] that is used to show that this decryption
can be done correctly. Specifically, given the current
`client_application_traffic_secret`, the necessary decryption key and iv
parameters can be generated. This is implemented and validated in `forge.c`.

The problem is that when done with an in-the-wild example, the SSL_read fails,
specifically in validating the GCM tag. The spec version generates the correct
tag, while the ITW does not.


## References

1. https://tools.ietf.org/html/rfc8448
2. https://tools.ietf.org/html/draft-ietf-tls-tls13-vectors-06
