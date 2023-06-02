#include "config.h"
#include "checks.h"
#include "ecdsa.h"
#include "log.h"
#include "secp256k1.h"

#include <stdbool.h>

// Returns true if the test vector fails but we intentional want to ignore.
static bool should_ignore_failure(const int vector_label) {
    switch (vector_label) {
      case 1: 
      // {
      //    "tcId": 1,
      //    "comment": "Signature malleability",
      //    "flags": ["SignatureMalleabilityBitcoin"],
      //    "msg": "313233343030",
      //    "sig": "3046022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc9832365022100900e75ad233fcc908509dbff5922647db37c21f4afd3203ae8dc4ae7794b0f87",
      //    "result": "invalid"
      // }

      // The signature is using the high s-value instead of the low one from [bip 62](https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki)
      // The [code in bitcoin](https://github.com/bitcoin/bitcoin/blob/v0.9.3/src/key.cpp#L202-L227) checks this. 
      // if (s > N/2)  { s := N - s }
      // The group order for secp256k1 is `N = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141`

      // HalfN := 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0
      // s     := 0x900e75ad233fcc908509dbff5922647db37c21f4afd3203ae8dc4ae7794b0f87
      // s > Half -> true
      return true;

      case 100:
      // {
      //    "tcId": 100,
      //    "comment": "truncated r",
      //    "flags": ["ModifiedSignature"],
      //    "msg": "313233343030",
      //    "sig": "30440220813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba",
      //    "result": "invalid"
      // }

      // The DER encoding does not encode leading zeros that it should. Here the signature's r-value is encoded as just a 0x20-byte long bignum, 
      // but it should be 0x21-byte long integer with a leading 0x00. The parser is a bit too lenient. However, we are not using this DER parser 
      // for anything other than testing.
      return true;

      case 388:
      // {
      //    "tcId": 388,
      //    "comment": "edge case for signature malleability",
      //    "flags": ["ArithmeticError"],
      //    "msg": "313233343030",
      //    "sig": "304402207fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a002207fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a1",
      //    "result": "invalid"
      // }

      // This is the same issue as vector 1 as this vector also uses the high s-value.
      // FIXME(sean): double check this! The comments in the test case don't align with what I remembered us finding. 
      return true;

      default: 
      return false;
    }
}

int verify_wycheproof(void) {
  #include "wycheproof/ecdsa_secp256k1_sha256_bitcoin_test.h"

  int failures = 0;
  int t;
  for (t = 0; t < SECP256K1_ECDSA_WYCHEPROOF_NUMBER_TESTVECTORS; t++) {
    // The json test vectors are 1-indexed.
    const int vector_label = t + 1;

    const unsigned char *msg, *der_sig, *pk;
    uint8_t sig[64] = {0};
    const ecdsa_curve *curve = &secp256k1;
    curve_point pub;

    pk = &wycheproof_ecdsa_public_keys[testvectors[t].pk_offset];

    int is_valid_pubkey = ecdsa_read_pubkey(curve, pk, &pub);
    if (is_valid_pubkey == 0) {
      ERROR("pub key not valid for test vector %d", vector_label);
      return -1;
    }

    msg = &wycheproof_ecdsa_messages[testvectors[t].msg_offset];
    der_sig = &wycheproof_ecdsa_signatures[testvectors[t].sig_offset];

    // returns non-zero if parsing fails, ignore the return value and continue with the verification.
    ecdsa_sig_from_der(der_sig, testvectors[t].sig_len, sig);

    // ecdsa_verify returns 0 if verification succeeds.
    int failed_verify = ecdsa_verify(curve, HASHER_SHA2, pk, sig, msg, testvectors[t].msg_len);

    // convert ecdsa_verify to match our test vectors. 0 = success, !0 = invalid.
    int passed_verify = (failed_verify == 0) ? 1 : 0;

    if (testvectors[t].expected_verify != passed_verify && !should_ignore_failure(vector_label)) {
      ERROR("wycheproof test vector failed [vector:%d][expected: %d][actual: %d]",
        vector_label,
        testvectors[t].expected_verify,
        passed_verify);

      failures++;
    }
  }

  if (failures != 0) {
    ERROR("%d test vectors failed.", failures);
  }

  return failures;
}
