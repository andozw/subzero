#include "init_wallet.h"

#include "log.h"

/**
 * Given a randomly generated byte buffer (master_seed), mixes additional
 * entropy provided by the host computer over RPC.
 *
 * We currently use XOR to mix the two buffers.
 * TODO(alok): replace with HMAC, which is slightly better.
 */
Result mix_entropy(uint8_t master_seed[static MASTER_SEED_SIZE],
                   const InternalCommandRequest* const in) {
  if (in->command.InitWallet.random_bytes.size != MASTER_SEED_SIZE) {
    ERROR("unexpected random_bytes.size");
    return Result_INCORRECT_RANDOM_BYTES_SIZE;
  }
  for (int i = 0; i < in->command.InitWallet.random_bytes.size; i++) {
    master_seed[i] = master_seed[i] ^ in->command.InitWallet.random_bytes.bytes[i];
  }

  return Result_SUCCESS;
}
