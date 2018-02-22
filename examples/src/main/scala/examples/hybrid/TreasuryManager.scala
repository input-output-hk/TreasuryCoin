package examples.hybrid

import treasury.crypto.core.Cryptosystem

object TreasuryManager {

  val cs = new Cryptosystem

  /* Intervals of an epoch stages in blocks (both Pos/Pow) */
  val EPOCH_LEN =                             111
  val REGISTER_RANGE =                        0 until 20
  val PROPOSAL_SUBMISSION_RANGE =             0 until 20
  val DISTR_KEY_GEN_R1_RANGE =                20 until 25
  val DISTR_KEY_GEN_R2_RANGE =                25 until 30
  val VOTING_RANGE =                          30 until 45
  val VOTING_DECRYPTION_R1_RANGE =            45 until 60
  val VOTING_DECRYPTION_R1_RECOVERY_RANGE =   60 until 70
  val VOTING_DECRYPTION_R2_RANGE =            70 until 85
  val VOTING_DECRYPTION_R2_RECOVERY_RANGE =   85 until 95
  val TALLY_SIGNING_RANGE =                   95 until 110
  val PAYMENT_BLOCK_HEIGHT =                  110

  object Role extends Enumeration {
    type Role = Value
    val Committee, Expert, Voter = Value
  }
}
