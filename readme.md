TLS Sandbox
===========

A simplified setup for testing Tapdance TLS forgery

* `client.go` is a client which connects to our TLS 1.3 decoy and dumps it's parameters
* `forge.c` takes crypto parameters and attempts to decrypt TLS packets
* `compat/` is all of OpenSSL's internal header files which allows forge.c to
  reach into opaque library objects
* `openssl/` is included as a submodule for introspection and to lock the version

## Building

* Run `make build-openssl` to build the linked version of openssl with
  debugging-friendly flags.
* Run `make debug` to build and run forge with gdb.
* `client.go` depends on some monkey-patched functions being added to
  `u_conn.go` in the utls library to access private data. Details are in the
  file.

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

We know that:

1. The decoy website (https://tls13.refraction.network) is using TLS v1.3 via
   Caddy.

2. uTLS is a valid TLS client because we are able to make requests and read
   responses from the decoy, which is https only.

3. The packet generated from uTLS is a valid TLS 1.3 packet because of it's
   contents and because of #2.

   a. It has the correct header 0x170303 + length

   b. It is the request content length + 5 (header) + 1 (real content type) + 16
   (auth tag)

4. The payload of the packet is decrypted.

   a. Run `make debug` to enter gdb with the decryption breakpoint set.

   b. In `ssl3_record_tls13.c:182`, `rec->data` contains the decrypted
   packet. The bytes are the value of the offset (e.g. `rec->data[3] == '\003'`)

   c. The last byte of the payload post-decryption is the application data
   record type (0x17 or '\027') `rec->data[rec->length - 1]`

5. The final failure is in the GCM tag validation.

   a. In `gcm128.c:1869`, `tag` is the auth tag from the packet, and `ctx->Xi.c`
   is the tag computed through the decryption process. These are not equal.


## References

1. https://tools.ietf.org/html/rfc8448
2. https://tools.ietf.org/html/draft-ietf-tls-tls13-vectors-06
