package examples.hybrid

import treasury.crypto.core.Cryptosystem

object TreasuryManager {

  lazy val cs = new Cryptosystem

  /* Durations of an epoch stages in blocks (both Pos/Pow) */
  val EPOCH_LEN = 500
  val REGISTER_STAGE_LEN = 50
  val DISTR_KEY_STAGE_LEN = 50
  val VOTING_STAGE_LEN = 50
  val VOTING_DECR_STAGE_LEN = 50
}
