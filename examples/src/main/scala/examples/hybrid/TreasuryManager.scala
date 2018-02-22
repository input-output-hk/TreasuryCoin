package examples.hybrid

import treasury.crypto.core.Cryptosystem

object TreasuryManager {

  val cs = new Cryptosystem

  /* Intervals of an epoch stages in blocks (both Pos/Pow). All numbers should be even. */
  val EPOCH_LEN =                             84
  val REGISTER_RANGE =                        0 until 20
  val PROPOSAL_SUBMISSION_RANGE =             0 until 20
  val DISTR_KEY_GEN_RANGE =                   20 until 24
  val VOTING_RANGE =                          24 until 40
  val VOTING_DECRYPTION_R1_RANGE =            40 until 50
  val VOTING_DECRYPTION_R1_RECOVERY_RANGE =   50 until 60
  val VOTING_DECRYPTION_R2_RANGE =            60 until 70
  val VOTING_DECRYPTION_R2_RECOVERY_RANGE =   70 until 80
  val TALLY_SIGNING_RANGE =                   80 until 82
  val PAYMENT_BLOCK_HEIGHT =                  82

  val BUDGET =                                1000

  object Role extends Enumeration {
    type Role = Value
    val Committee, Expert, Voter = Value
  }
}
