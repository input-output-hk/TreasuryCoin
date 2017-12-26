package examples.hybrid

import treasury.crypto.core.Cryptosystem

object TreasuryManager {

  lazy val cs = new Cryptosystem

  /* Intervals of an epoch stages in blocks (both Pos/Pow) */
  val EPOCH_LEN =         500
  val REGISTER_STAGE =    (0, 499)  // for testing purpose a register stage is set to be entire epoch
  val DISTR_KEY_STAGE =   (100, 199)
  val VOTING_STAGE =      (200, 399)
  val VOTING_DECR_STAGE = (400, 499)
}
