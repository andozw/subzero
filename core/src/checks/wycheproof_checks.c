// TODO
#include "config.h"
#include "checks.h"
#include "log.h"

int verify_wycheproof(void) {
  #include "wycheproof/ecdsa_secp256k1_sha256_bitcoin_test.h"
  INFO("foobar 373737!");

  int t;
  for (t = 0; t < SECP256K1_ECDSA_WYCHEPROOF_NUMBER_TESTVECTORS; t++) {
    INFO("***");
    const unsigned char *msg, *sig, *pk;
    (void)msg;
    (void)sig;
    (void)pk;

    // trezor pubkey...
    const uint8_t *pubkey;
    memset(&pubkey, 0, sizeof(pubkey));

    //   const ecdsa_curve *curve = &secp256k1;
    // int ecdsa_read_pubkey(const ecdsa_curve *curve, const uint8_t *pub_key, curve_point *pub) {

    pk = &wycheproof_ecdsa_public_keys[testvectors[t].pk_offset];

    msg = &wycheproof_ecdsa_messages[testvectors[t].msg_offset];

    sig = &wycheproof_ecdsa_signatures[testvectors[t].sig_offset];

  }

  return 0;
}
