package examples.hybrid

import treasury.crypto.core.Cryptosystem

object TreasuryManager {

  val cs = new Cryptosystem

  /* Intervals of an epoch stages in blocks (both Pos/Pow) */
  val EPOCH_LEN =                             111
  val REGISTER_RANGE =                        0 until 15
  val PROPOSAL_SUBMISSION_RANGE =             0 until 15
  val DISTR_KEY_GEN_R1_RANGE =                15 until 20 // 18
  val DISTR_KEY_GEN_R2_RANGE =                20 until 26
  val DISTR_KEY_GEN_R3_RANGE =                26 until 34
  val DISTR_KEY_GEN_R4_RANGE =                34 until 42
  val DISTR_KEY_GEN_R5_RANGE =                42 until 50
  val VOTING_RANGE =                          50 until 58
  val VOTING_DECRYPTION_R1_RANGE =            58 until 75
  val VOTING_DECRYPTION_R1_RECOVERY_RANGE =   75 until 85
  val VOTING_DECRYPTION_R2_RANGE =            85 until 100
  val VOTING_DECRYPTION_R2_RECOVERY_RANGE =   100 until 110
  val TALLY_SIGNING_RANGE =                   110 until 120
  val PAYMENT_BLOCK_HEIGHT =                  120

  object Role extends Enumeration {
    type Role = Value
    val Committee, Expert, Voter = Value
  }
}
