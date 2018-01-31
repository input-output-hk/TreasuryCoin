package examples.hybrid

import treasury.crypto.core.Cryptosystem

object TreasuryManager {

  lazy val cs = new Cryptosystem

  /* Intervals of an epoch stages in blocks (both Pos/Pow) */
  val EPOCH_LEN =                 500
  val REGISTER_RANGE =            0 until 30
  val PROPOSAL_SUBMISSION_RANGE = 0 until 30
  val DISTR_KEY_GEN_RANGE =       30 until 35
  val VOTING_RANGE =              35 until 200
  val VOTING_DECR_RANGE =         200 until 500

  object Role extends Enumeration {
    type Role = Value
    val Committee, Expert, Voter = Value
  }
}
