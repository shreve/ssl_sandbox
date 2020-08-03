TLS Sandbox
===========

A simplified setup for testing Tapdance TLS forgery

* `client.go` is a client which connects to our TLS 1.3 decoy and dumps it's parameters
* `forge.c` takes crypto parameters and attempts to decrypt TLS packets
* `compat/` is all of OpenSSL's internal header files which allows forge.c to
  reach into opaque library objects
