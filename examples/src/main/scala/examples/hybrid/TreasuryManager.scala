package examples.hybrid

import treasury.crypto.core.Cryptosystem

object TreasuryManager {

  lazy val cs = new Cryptosystem

  /* Intervals of an epoch stages in blocks (both Pos/Pow) */
  val EPOCH_LEN =                 50
  val REGISTER_RANGE =            0 until 20
  val PROPOSAL_SUBMISSION_RANGE = 0 until 20
  val DISTR_KEY_GEN_RANGE =       20 until 25
  val VOTING_RANGE =              25 until 45
  val VOTING_DECR_RANGE =         45 until 50

  object Role extends Enumeration {
    type Role = Value
    val Committee, Expert, Voter = Value
  }
}
