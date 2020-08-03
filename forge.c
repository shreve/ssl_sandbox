#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include "compat/compat.h"
#include <assert.h>

#define IVLEN   12
#define KEYLEN  16
#define TLS13_MAX_LABEL_LEN     249

void printhex(const unsigned char *ptr, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", ptr[i]);
    }
    printf("\n");
}

#define hex2bytes(x) OPENSSL_hexstr2buf(x, NULL);

int main() {

    // Initialize OpenSSL
    SSL_library_init();
    SSL_load_error_strings();

    // Make a new SSL session
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    SSL *s = SSL_new(ctx);

    // Create blank BIO
    SSL_set_bio(s, BIO_new(BIO_s_mem()), BIO_new(BIO_s_mem()));

    // Get crypto parameters
    const EVP_CIPHER *ciph = EVP_aes_128_gcm();
    size_t keylen = EVP_CIPHER_key_length(ciph);
    size_t ivlen = EVP_CIPHER_iv_length(ciph);
    const EVP_MD *md = EVP_sha256();

    // https://tools.ietf.org/html/draft-ietf-tls-tls13-vectors-06
    // {client}  derive write traffic keys for application data:
    unsigned char *client_app_traffic_secret = hex2bytes("e2f0db6a82e88280fc26f73c89854ee8615e25df28b2207962fa782226b23626");
    unsigned char *correct_key = hex2bytes("88b96ad686c84be55ace18a59cce5c87");
    unsigned char *correct_iv = hex2bytes("b99dc58cd5ff5ab082fdad19");
    int secretlen = 32;

    unsigned char static_key[keylen];
    tls13_derive_key(s, md, client_app_traffic_secret, static_key, keylen);
    assert(strncmp(static_key, correct_key, keylen) == 0);

    unsigned char static_iv[ivlen];
    tls13_derive_iv(s, md, client_app_traffic_secret, static_iv, ivlen);
    assert(strncmp(static_iv, correct_iv, ivlen) == 0);

    // {client}  send application_data record:
    unsigned char *correct_payload = hex2bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031");
    unsigned char *client_packet = hex2bytes("17030300438c3497da00ae023e53c01b4324b665404c1b49e78fe2bf4d17f6348ae8340551e363a0cd05f2179c4fef5ad689b5cae0bae94adc63632e571fb79aa91544c6394d28a1");


    if (1) {
        // This block attempts to decrypt the payload from within the packet.
        unsigned char *enc_payload = client_packet + 5;
        unsigned char read_payload[50];
        int read_bytes;
        s->enc_read_ctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(s->enc_read_ctx, ciph, NULL, correct_key, correct_iv);
        EVP_DecryptUpdate(s->enc_read_ctx, read_payload, &read_bytes, enc_payload, 50);
        EVP_DecryptFinal(s->enc_read_ctx, read_payload + read_bytes, &read_bytes);
        assert(strncmp(read_payload, correct_payload, 50) == 0);
    }


    // We now have all the data we need (client app traffic secret and packet)
    // Now we need to write into an SSL object and read the payload back out.


    // NOW BEGINS THE FORGERY MAGIC
    memcpy(s->client_app_traffic_secret, client_app_traffic_secret, secretlen);
    memcpy(s->read_iv, correct_iv, ivlen);
    memcpy(s->write_iv, correct_iv, ivlen);

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
        return -1;
    }

    if (!ssl3_setup_buffers(s)) {
        fprintf(stderr, "Couldn't setup ssl3 buffers\n");
        return -1;
    }

    s->s3->tmp.new_cipher =
        (SSL_CIPHER*)ssl3_get_cipher_by_char(
            (const unsigned char*)"\x13\x01");
    s->session->cipher = s->s3->tmp.new_cipher;

    if (!s->method->ssl3_enc->setup_key_block(s)) {
        fprintf(stderr, "Couldn't setup key block\n");
        return -1;
    }

    s->rlayer.write_sequence[7] = '\x00';
    s->rlayer.read_sequence[7] = '\x00';

    // Key location: (*(EVP_AES_GCM_CTX *)ctx->cipher_data).gcm.key
    // IV location: (*(EVP_AES_GCM_CTX *)ctx->cipher_data).gcm.Yi.c
    s->enc_read_ctx = EVP_CIPHER_CTX_new();
    EVP_CipherInit_ex(s->enc_read_ctx, ciph, NULL, correct_key, NULL, 0);

    s->enc_write_ctx = EVP_CIPHER_CTX_new();
    EVP_CipherInit_ex(s->enc_write_ctx, ciph, NULL, correct_key, NULL, 1);

    // Write the client packet into the RBIO
    BIO *rbio = SSL_get_rbio(s);
    int len = 72;
    if (BIO_write(rbio, client_packet, len) != len) {
        fprintf(stderr, "ssl_decrypt: couldn't write to BIO!\n");
        return -1;
    }

    // Try to read back out
    char payload[50]; // Expected payload is 50 bytes
    int ret = SSL_read(s, payload, 50);
    if (ret <= 0) {
        printf("Read failed.\n");
        return 1;
    }

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

    assert(strncmp(payload, correct_payload, 50) == 0);

    // Now that we've read the payload out, we need to make sure we send it back correctly.
    ret = SSL_write(s, payload, 50);
    assert(ret == 50);

    unsigned char *correct_server_packet = hex2bytes("1703030043f65f49fd2df6cd2347c3d30166e3cfddb6308a5906c076112c6a37ff1dbd406b5813c0abd734883017a6b2833186b13c14da5d75f33d8760789994e27d82043ab88d65");

    BIO *wbio = SSL_get_wbio(s);
    unsigned char *server_packet;
    long packet_len = BIO_get_mem_data(wbio, &server_packet);
    assert(packet_len == 72);
    assert(strncmp(server_packet, correct_server_packet, packet_len) == 0);

    // One more test, receiving alert record
    unsigned char *client_alert_packet = hex2bytes("17030300132c2148163d7938a35f6acf2a6606f8cbd1d9f2");

    len = 24;
    assert(BIO_eof(rbio));
    assert(BIO_write(rbio, client_alert_packet, len) == len);
    ret = SSL_read(s, payload, 2);
    assert(ret == 0);
    assert(s->shutdown & SSL_RECEIVED_SHUTDOWN);

    printf("Success.\n");

    return 0;
}
