// TODO
#include "config.h"
#include "checks.h"
#include "log.h"
#include "ecdsa.h"
#include "secp256k1.h"

int verify_wycheproof(void) {
  #include "wycheproof/ecdsa_secp256k1_sha256_bitcoin_test.h"
  INFO("foobar 473737!");

  int failures = 0;

  int t;
  for (t = 0; t < SECP256K1_ECDSA_WYCHEPROOF_NUMBER_TESTVECTORS; t++) {
  /*for (t = 0; t < 2; t++) {*/
    const unsigned char *msg, *der_sig, *pk;
    (void)msg;
    (void)der_sig;
    (void)pk;

    // trezor pubkey...
    /*uint8_t pubkey[64];*/
    /*memset(pubkey, 0, sizeof(pubkey));*/


    /*int ecdsa_validate_pubkey(const ecdsa_curve *curve, const curve_point *pub);*/
/*int ecdsa_verify(const ecdsa_curve *curve, HasherType hasher_sign,*/
                 /*const uint8_t *pub_key, const uint8_t *sig, const uint8_t *msg,*/
                 /*uint32_t msg_len);*/

    pk = &wycheproof_ecdsa_public_keys[testvectors[t].pk_offset];
    DEBUG("Test Case: %d: ", t + 1);

    const ecdsa_curve *curve = &secp256k1;
    curve_point pub;

    int is_valid_pubkey = ecdsa_read_pubkey(curve, pk, &pub);
    /*printf("pubkey valid: %d\n", is_valid_pubkey);*/
    (void)is_valid_pubkey;

    msg = &wycheproof_ecdsa_messages[testvectors[t].msg_offset];
    der_sig = &wycheproof_ecdsa_signatures[testvectors[t].sig_offset];

    uint8_t sig[64] = {0};

    int temp = ecdsa_sig_from_der(der_sig, testvectors[t].sig_len, sig);

    if (temp != 0) {
      ERROR("WTF parsing sig from der: %d", temp);
    }

    printf("public key: ");
    for (int i = 0; i < 65; i++) {
      printf("%02x", pk[i]);
    }
    printf("\n");

    printf("signature: ");
    for (size_t i = 0; i < testvectors[t].sig_len; i++) {
      printf("%02x", der_sig[i]);
    }
    printf("\n");

    // ecdsa_verify returns 0 if verification succeeds.
    int invalid_sig = ecdsa_verify(curve, HASHER_SHA2, pk, sig, msg, testvectors[t].msg_len);
    printf("ecdsa_verify returned: [%d]\n", invalid_sig);

    // convert ecdsa_verify to match our test vectors. 0 = success, !0 = invalid.
    int actual_verify = (invalid_sig == 0) ? 1 : 0;

    /*if (actual_verify == 1) {*/
      /*printf("Actually valid! %d\n", t);*/
      /*for (int i = 0; i < 65; i++) {*/
        /*printf("%02x", pk[i]);*/
      /*}*/
      /*printf("\n");*/
    /*}*/
    /*continue; */

    if (testvectors[t].expected_verify != actual_verify) {
      ERROR("wycheproof test vector failed [vector:%d][expected: %d][actual: %d]",
            t,
            testvectors[t].expected_verify,
            actual_verify);
      printf("ecdsa_verify returned: [%d]\n", invalid_sig);
      for (unsigned long i = 0; i < testvectors[t].sig_len; i++) {
        printf("%02x", der_sig[i]);
      }
      printf("\n");

      failures++;
    }
  }

  if (failures != 0) {
    ERROR("%d test vectors failed.", failures);
  }

  return 0;
}
