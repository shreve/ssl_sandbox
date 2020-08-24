#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include "compat/compat.h"
#include <assert.h>

typedef unsigned char *  bytes;

void printhex(const bytes ptr, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", ptr[i]);
    }
    printf("\n");
}

#define hex2bytes(x) OPENSSL_hexstr2buf(x, NULL);

// State setup for forging socket. None of this needs priviledged info.
SSL *setup_ssl() {
    // Initialize OpenSSL
    SSL_library_init();
    SSL_load_error_strings();

    // Make a new SSL session
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    SSL *s = SSL_new(ctx);

    // Create blank BIO
    SSL_set_bio(s, BIO_new(BIO_s_mem()), BIO_new(BIO_s_mem()));

    // State that we are done with the handshake and certs look valid
    s->statem.hand_state = TLS_ST_OK;
    s->statem.state = MSG_FLOW_READING;
    s->statem.no_cert_verify = 1;
    SSL_set_accept_state(s);
    SSL_set_ssl_method(s, tlsv1_3_server_method());
    SSL_set_verify_result(s, X509_V_OK);
    s->rwstate = SSL_NOTHING;
    s->statem.in_handshake = 0;
    s->statem.in_init = 0;
    s->new_session = 0;
    s->quiet_shutdown = 0;
    s->shutdown = 0;

    if (!ssl_get_new_session(s, 0)) {
        fprintf(stderr, "Couldn't get session\n");
        exit(1);
    }

    if (!ssl3_setup_buffers(s)) {
        fprintf(stderr, "Couldn't setup ssl3 buffers\n");
        exit(1);
    }

    s->rlayer.write_sequence[7] = 0;
    s->rlayer.read_sequence[7] = 0;

    s->enc_read_ctx = EVP_CIPHER_CTX_new();
    s->enc_write_ctx = EVP_CIPHER_CTX_new();

    // TLS_AES_128_GCM_SHA256
    s->s3->tmp.new_cipher =
        (SSL_CIPHER*)ssl3_get_cipher_by_char(
            (const unsigned char*)"\x13\x01");
    s->session->cipher = s->s3->tmp.new_cipher;

    if (!s->method->ssl3_enc->setup_key_block(s)) {
        fprintf(stderr, "Couldn't setup key block\n");
        exit(1);
    }

    return s;
}

// Use the provided traffic secret to set up decryption ciphers.
void use_secret(SSL *s, bytes traffic_secret) {
    const EVP_CIPHER *ciph = EVP_aes_128_gcm();
    size_t keylen = EVP_CIPHER_key_length(ciph);
    size_t ivlen = EVP_CIPHER_iv_length(ciph);
    size_t secretlen = 32;
    const EVP_MD *md = EVP_sha256();

    unsigned char static_key[keylen];
    tls13_derive_key(s, md, traffic_secret, static_key, keylen);
    printf("Key: ");
    printhex(static_key, keylen);

    unsigned char static_iv[ivlen];
    tls13_derive_iv(s, md, traffic_secret, static_iv, ivlen);
    printf("IV: ");
    printhex(static_iv, ivlen);

    memcpy(s->client_app_traffic_secret, traffic_secret, secretlen);
    memcpy(s->read_iv, static_iv, ivlen);
    memcpy(s->write_iv, static_iv, ivlen);

    EVP_CipherInit_ex(s->enc_read_ctx, ciph, NULL, static_key, NULL, 0);
    EVP_CipherInit_ex(s->enc_write_ctx, ciph, NULL, static_key, NULL, 1);
}

void decrypt_and_read(bytes secret, bytes packet) {
    SSL *s = setup_ssl();

    use_secret(s, secret);

    // Read length supplied in packet
    uint16_t packet_body_length = (packet[3] << 8) | packet[4];

    // Total length is that plus header, 5 bytes
    uint16_t packet_length = packet_body_length + 5;

    // Length of original payload is total - (1 (masked type) + 16 (auth tag))
    uint16_t payload_length = packet_body_length - 17;

    // Write the client packet into the RBIO
    BIO *rbio = SSL_get_rbio(s);
    if (BIO_write(rbio, packet, packet_length) != packet_length) {
        fprintf(stderr, "ssl_decrypt: couldn't write to BIO!\n");
        return;
    }

    // Try to read back out
    unsigned char read_payload[payload_length + 1];
    int ret = SSL_read(s, read_payload, payload_length + 1);
    if (ret <= 0) {
        printf("Read failed.\n");
        return;
    }

    printhex(read_payload, ret);
    printf("Success.\n");
}


int main() {

    // draft values https://tools.ietf.org/html/draft-ietf-tls-tls13-vectors-06
    bytes traffic_secret = hex2bytes("e2f0db6a82e88280fc26f73c89854ee8615e25df28b2207962fa782226b23626");
    bytes packet = hex2bytes("17030300438c3497da00ae023e53c01b4324b665404c1b49e78fe2bf4d17f6348ae8340551e363a0cd05f2179c4fef5ad689b5cae0bae94adc63632e571fb79aa91544c6394d28a1");

    printf("\nReading spec example.\n");
    decrypt_and_read(traffic_secret, packet);

    // values from final RFC https://tools.ietf.org/html/rfc8448
    traffic_secret = hex2bytes("2abbf2b8e381d23dbebe1dd2a7d16a8bf484cb4950d23fb7fb7fa8547062d9a1");
    packet = hex2bytes("1703030043b1cebce242aa201be9ae5e1cb2a9aa4b33d4e866af1edb068919237741aa031d7a74d491c99b9d4e232b74206bc6fbaa04fe78be44a9b4f54320a17eb76992afac3103");

    printf("\nReading RFC example.\n");
    decrypt_and_read(traffic_secret, packet);

    // Generated from client.go
    traffic_secret = hex2bytes("a3ad003da74fe279562e25debfc7a71885af48c7124e37f61db555e84e54d349");
    packet = hex2bytes("17030300430b06d55321168eb051caf995a078dc350e483b14e9f1def946f58460b39dca374cd4160aeadaf1d969be20b5e86debb7c6970bccdb9580eae3a5e46a3ebba4053301a4");

    printf("\nReading request from client.go.\n");
    decrypt_and_read(traffic_secret, packet);

}

// Don't mind the mess


    // Get crypto parameters

    // {client}  derive write traffic keys for application data:
    // bytes client_app_traffic_secret = hex2bytes("e2f0db6a82e88280fc26f73c89854ee8615e25df28b2207962fa782226b23626");
    /* bytes correct_key = hex2bytes("88b96ad686c84be55ace18a59cce5c87"); */
    /* bytes correct_iv = hex2bytes("b99dc58cd5ff5ab082fdad19"); */

    // {client}  send application_data record:
    /* bytes correct_payload = hex2bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031"); */

    /* if (1) { */
    /*     // This block attempts to decrypt the payload from within the packet. */
    /*     bytes enc_payload = client_packet + 5; */
    /*     unsigned char read_payload[50]; */
    /*     int read_bytes; */
    /*     s->enc_read_ctx = EVP_CIPHER_CTX_new(); */
    /*     EVP_DecryptInit_ex(s->enc_read_ctx, ciph, NULL, correct_key, correct_iv); */
    /*     EVP_DecryptUpdate(s->enc_read_ctx, read_payload, &read_bytes, enc_payload, 50); */
    /*     EVP_DecryptFinal(s->enc_read_ctx, read_payload + read_bytes, &read_bytes); */
    /*     assert(strncmp(read_payload, correct_payload, 50) == 0); */
    /* } */


    // We now have all the data we need (client app traffic secret and packet)
    // Now we need to write into an SSL object and read the payload back out.


    // assert(strncmp(payload, correct_payload, 50) == 0);

    // ssl3_record.c:410 -- reading body bytes
    // rec_layer_s3.c:296 -- reading out of the RBIO
    // ssl3_record_tls13.c:178 -- decryption of packet payload
    // evp_enc.c:484 -- telling AES_GCM cipher to do it's thing
    // e_aes.c:3258 -- perform CRYPTO_gcm128_decrypt
    //                  this call is full of 0s and quickly returns 0
    // e_aes.c:3261 -- perform AES_gcm_decrypt
    //                  this is an assembly function so I can't really follow
    //                  it gets called with same 0s and returns 0, seems to change nothing
    // e_aes.c:3269 -- perform CRYPTO_gcm128_decrypt_ctr32
    //                  actually gets the 51 length
    //                  calls functions that seem to perform GCM (GHASH)
    //                  doesn't actually result in change. in/out are same before/after.


    /*
    // Now that we've read the payload out, we need to make sure we send it back correctly.
    ret = SSL_write(s, payload, 50);
    assert(ret == 50);

    bytes correct_server_packet = hex2bytes("1703030043f65f49fd2df6cd2347c3d30166e3cfddb6308a5906c076112c6a37ff1dbd406b5813c0abd734883017a6b2833186b13c14da5d75f33d8760789994e27d82043ab88d65");

    BIO *wbio = SSL_get_wbio(s);
    bytes server_packet;
    long packet_len = BIO_get_mem_data(wbio, &server_packet);
    assert(packet_len == 72);
    assert(strncmp(server_packet, correct_server_packet, packet_len) == 0);

    // One more test, receiving alert record
    bytes client_alert_packet = hex2bytes("17030300132c2148163d7938a35f6acf2a6606f8cbd1d9f2");

    int len = 24;
    assert(BIO_eof(rbio));
    assert(BIO_write(rbio, client_alert_packet, len) == len);
    ret = SSL_read(s, payload, 2);
    assert(ret == 0);
    assert(s->shutdown & SSL_RECEIVED_SHUTDOWN);

    printf("Success.\n");

    return 0;
    */

/*
// Get the keystream rather than decrypting.
int get_keystream(SSL *s, bytes out, size_t len,
                  bytes traffic_secret) {
    bytes in = malloc(len);
    int read = 0;
    memset(in, 0, len);
    memset(out, 0, len);

    const EVP_CIPHER *ciph = EVP_aes_128_gcm();
    size_t keylen = EVP_CIPHER_key_length(ciph);
    size_t ivlen = EVP_CIPHER_iv_length(ciph);
    const EVP_MD *md = EVP_sha256();

    unsigned char static_key[keylen];
    tls13_derive_key(s, md, traffic_secret, static_key, keylen);
    unsigned char static_iv[ivlen];
    tls13_derive_iv(s, md, traffic_secret, static_iv, ivlen);

    EVP_CipherInit_ex(s->enc_read_ctx, ciph, NULL, static_key, NULL, 0);
    EVP_CipherInit_ex(s->enc_write_ctx, ciph, NULL, static_key, NULL, 1);

    EVP_DecryptInit_ex(s->enc_read_ctx, ciph, NULL, static_key, static_iv);
    EVP_DecryptUpdate(s->enc_read_ctx, out, &read, in, len);
    EVP_DecryptFinal(s->enc_read_ctx, out + read, &read);
    free(in);
    return read;
}

bytes xor(const bytes left, const bytes right, size_t len) {
    bytes xor = malloc(len);
    for (size_t i = 0; i < len; i++) {
        xor[i] = left[i] ^ right[i];
    }
    return xor;
}

void printdivergence(const bytes left, const bytes right, size_t len) {
    size_t i = 0;
    for (; i < len; i++) {
        if (left[i] != right[i]) {
            break;
        }
    }
    printf("First %d bytes the same. Printing remaining %d.\n",
           (int)(i), (int)(len - i - 1));
    for (size_t j = i; j < len; j++) {
        printf("%02x", left[j]);
    }
    printf("\n");
    for (; i < len; i++) {
        printf("%02x", right[i]);
    }
    printf("\n");
}
*/
