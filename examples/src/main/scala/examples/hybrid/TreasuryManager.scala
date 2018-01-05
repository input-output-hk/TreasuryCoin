package examples.hybrid

import treasury.crypto.core.Cryptosystem

object TreasuryManager {

  lazy val cs = new Cryptosystem

  /* Intervals of an epoch stages in blocks (both Pos/Pow) */
  val EPOCH_LEN =                 500
  val REGISTER_RANGE =            0 until 500  // for testing purpose a register stage is set to be entire epoch
  val PROPOSAL_SUBMISSION_RANGE = 0 until 500
  val DISTR_KEY_GEN_RANGE =       100 until 200
  val VOTING_RANGE =              200 until 400
  val VOTING_DECR_RANGE =         400 until 500
}
