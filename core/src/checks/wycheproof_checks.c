// TODO
#include "config.h"
#include "checks.h"
#include "log.h"
#include "ecdsa.h"
#include "secp256k1.h"

int verify_wycheproof(void) {
  #include "wycheproof/ecdsa_secp256k1_sha256_bitcoin_test.h"
  INFO("foobar 473737!");

  int t;
  for (t = 0; t < SECP256K1_ECDSA_WYCHEPROOF_NUMBER_TESTVECTORS; t++) {
    INFO("***");
    const unsigned char *msg, *sig, *pk;
    (void)msg;
    (void)sig;
    (void)pk;

    // trezor pubkey...
    /*uint8_t pubkey[64];*/
    /*memset(pubkey, 0, sizeof(pubkey));*/


    /*int ecdsa_validate_pubkey(const ecdsa_curve *curve, const curve_point *pub);*/
/*int ecdsa_verify(const ecdsa_curve *curve, HasherType hasher_sign,*/
                 /*const uint8_t *pub_key, const uint8_t *sig, const uint8_t *msg,*/
                 /*uint32_t msg_len);*/

    pk = &wycheproof_ecdsa_public_keys[testvectors[t].pk_offset];
    printf("Test Case: %d: ", t);

    for (int i = 0; i < 65; i++) {
      printf("%02x", pk[i]);
    }
    printf("\n");

    const ecdsa_curve *curve = &secp256k1;
    curve_point pub;

    int is_valid_pubkey = ecdsa_read_pubkey(curve, pk, &pub);
    printf("pubkey valid: %d\n", is_valid_pubkey);

    msg = &wycheproof_ecdsa_messages[testvectors[t].msg_offset];
    sig = &wycheproof_ecdsa_signatures[testvectors[t].sig_offset];

    int is_valid_sig = ecdsa_verify(curve, HASHER_SHA2, pk, sig, msg, testvectors[t].msg_len);

    printf("sig valid: %d\n\n", is_valid_sig);
  }

  return 0;
}
