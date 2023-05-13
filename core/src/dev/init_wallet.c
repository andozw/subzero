#include "init_wallet.h"

#include "bip32.h"
#include "bip39.h"
#include "checks.h"
#include "config.h"
#include "curves.h"
#include "log.h"
#include "protection.h"
#include "rand.h"
#include "rpc.h"

#include <assert.h>
#include <pb_decode.h>
#include <pb_encode.h>
#include <squareup/subzero/common.pb.h>
#include <squareup/subzero/internal.pb.h>
#include <stdio.h>

/**
 * Initialize a wallet.
 * in prod:
 *   - derive master_seed_encryption_key from the ticket
 *   - derive pub_key_encryption_key from the ticket
 *   - generate 64 bytes of randomly generates bytes using the nCipher
 *   - xor with the randomly generated bytes in the rpc.
 *   - derive the pubkey
 *   - encrypt the master_seed and pubkey
 *
 * in dev:
 *   - randomly generate 32 bytes
 *   - xor with the randomly generated bytes in the rpc.
 *   - derive the mnemonic. Print it out for debugging.
 *   - derive the master_seed
 *   - derive the pubkey
 *   - encrypt the master_seed and pubkey
 */
Result handle_init_wallet(const InternalCommandRequest* const in,
                          InternalCommandResponse_InitWalletResponse *out) {

  uint8_t entropy[MASTER_SEED_SIZE] = {0};
  random_buffer(entropy, sizeof(entropy));
  Result r = mix_entropy(entropy, in);
  if (r != Result_SUCCESS) {
    ERROR("mix_entropy failed");
    return r;
  }

  // Only use 32 bytes of entropy to derive mnemonic and print it to stdout for
  // debugging purpose.
  const char *mnemonic = mnemonic_from_data(entropy, 32);
  DEBUG("mnemonic: %s", mnemonic);

  uint8_t master_seed[MASTER_SEED_SIZE];
  // todo: error handling
  static_assert(MASTER_SEED_SIZE >= 64, "MASTER_SEED_SIZE too small");
  mnemonic_to_seed(mnemonic, "", master_seed, NULL);

  HDNode node;
  // TODO: error handling!
  hdnode_from_seed(master_seed, sizeof(master_seed), SECP256K1_NAME, &node);

  // We have to perform the first derivation (0' for Mainnet, 1' for Testnet) before getting
  // the pubkey
  // TODO: error handling!
  uint32_t fingerprint = hdnode_fingerprint(&node);
  hdnode_private_ckd_prime(&node, COIN_TYPE);
  hdnode_fill_public_key(&node);

  char pub_key[128];
  int ret = hdnode_serialize_public(&node, fingerprint, PUBKEY_PREFIX,
                                    pub_key, sizeof(pub_key));
  if (ret <= 0) {
    // TODO: create an error code for serialization failure?
    return Result_UNKNOWN_INTERNAL_FAILURE;
  }
  DEBUG("pub key m/1': %s", pub_key);

  // encrypt master_seed and pub_key
  r = protect_wallet(master_seed, &out->encrypted_master_seed);
  if (r != Result_SUCCESS) {
    ERROR("protect_wallet failed: (%d).", r);
    return r;
  }
  r = protect_pubkey(pub_key, &out->encrypted_pub_key);
  if (r != Result_SUCCESS) {
    ERROR("protect_pubkey failed: (%d).", r);
    return r;
  }

  return Result_SUCCESS;
}
