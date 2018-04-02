package examples.hybrid

import scorex.core.transaction.box.proposition.PublicKey25519Proposition
import scorex.crypto.signatures.{Curve25519, PublicKey}
import treasury.crypto.core.Cryptosystem

object TreasuryManager {

  val cs = new Cryptosystem

  /* Intervals of an epoch stages in blocks (both Pos/Pow). All numbers should be even. */
  val EPOCH_LEN =                             186
  val PROPOSAL_SUBMISSION_RANGE =             4 until 20
  val VOTER_REGISTER_RANGE =                  4 until 14
  val EXPERT_REGISTER_RANGE =                 14 until 24
  val RANDOMNESS_DECRYPTION_RANGE =           24 until 34
  val RANDOMNESS_DECRYPTION_RECOVERY_RANGE =  34 until 44
  val DISTR_KEY_GEN_R1_RANGE =                44 until 56
  val DISTR_KEY_GEN_R2_RANGE =                56 until 68
  val DISTR_KEY_GEN_R3_RANGE =                68 until 80
  val DISTR_KEY_GEN_R4_RANGE =                80 until 92
  val DISTR_KEY_GEN_R5_RANGE =                92 until 104
  val VOTING_RANGE =                          104 until 120
  val VOTING_DECRYPTION_R1_RANGE =            120 until 132
  val VOTING_DECRYPTION_R1_RECOVERY_RANGE =   132 until 144
  val VOTING_DECRYPTION_R2_RANGE =            144 until 156
  val VOTING_DECRYPTION_R2_RECOVERY_RANGE =   156 until 168
  val RANDOMNESS_SUBMISSION_RANGE =           168 until 180
  val PENALTY_BLOCK_HEIGHT =                  182
  val PAYMENT_BLOCK_HEIGHT =                  184

  /* Constants related to reward distribution */
  val BUDGET =               1000
  val PROPOSALS_BUDGET =     0.7 * BUDGET
  val VOTERS_BUDGET =        0.1 * BUDGET
  val COMMITTEE_BUDGET =     0.1 * BUDGET
  val EXPERTS_BUDGET =       0.1 * BUDGET

  /* Constants related to deposits */
  val VOTER_DEPOSIT_RANGE = 10 to 1000
  val EXPERT_DEPOSIT_RANGE = 100 to 100 // fixed deposit
  val COMMITTEE_DEPOSIT_RANGE = 100 to 100
  val DEPOSIT_LOCK_PERIOD = 1 // should be at least 1 otherwise RandGen penalties should be disabled (cause they are possible only in the next epoch)
  val VOTER_DEPOSIT_ADDR = PublicKey25519Proposition(PublicKey @@ Array.fill[Byte](Curve25519.KeyLength)(0.toByte)) // actually it's a proof of burn address
  val COMMITTEE_DEPOSIT_ADDR = PublicKey25519Proposition(PublicKey @@ Array.fill[Byte](Curve25519.KeyLength)(1.toByte)) // actually it's a proof of burn address

  /* How much committee members are allowed in a single epoch */
  val COMMITTEE_SIZE = 10

  object Role extends Enumeration {
    type Role = Value
    val Committee, Expert, Voter = Value
  }
}
