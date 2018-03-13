package examples.hybrid

import scorex.core.transaction.box.proposition.PublicKey25519Proposition
import scorex.crypto.signatures.{Curve25519, PublicKey}
import treasury.crypto.core.Cryptosystem

object TreasuryManager {

  val cs = new Cryptosystem

  /* Intervals of an epoch stages in blocks (both Pos/Pow). All numbers should be even. */
  val EPOCH_LEN =                             114
  val PROPOSAL_SUBMISSION_RANGE =             4 until 20
  val VOTER_REGISTER_RANGE =                  4 until 14
  val EXPERT_REGISTER_RANGE =                 14 until 24
  val DISTR_KEY_GEN_R1_RANGE =                24 until 30
  val DISTR_KEY_GEN_R2_RANGE =                30 until 36
  val DISTR_KEY_GEN_R3_RANGE =                36 until 42
  val DISTR_KEY_GEN_R4_RANGE =                42 until 48
  val DISTR_KEY_GEN_R5_RANGE =                48 until 54
  val VOTING_RANGE =                          54 until 70
  val VOTING_DECRYPTION_R1_RANGE =            70 until 80
  val VOTING_DECRYPTION_R1_RECOVERY_RANGE =   80 until 90
  val VOTING_DECRYPTION_R2_RANGE =            90 until 100
  val VOTING_DECRYPTION_R2_RECOVERY_RANGE =   100 until 110
  val TALLY_SIGNING_RANGE =                   110 until 112
  val PAYMENT_BLOCK_HEIGHT =                  112

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
  val DEPOSIT_LOCK_PERIOD = 0 // in epochs
  val VOTER_DEPOSIT_ADDR = PublicKey25519Proposition(PublicKey @@ Array.fill[Byte](Curve25519.KeyLength)(0.toByte)) // actually it's a proof of burn address
  val COMMITTEE_DEPOSIT_ADDR = PublicKey25519Proposition(PublicKey @@ Array.fill[Byte](Curve25519.KeyLength)(1.toByte)) // actually it's a proof of burn address

  /* How much committee members are allowed in a single epoch */
  val COMMITTEE_SIZE = 10

  object Role extends Enumeration {
    type Role = Value
    val Committee, Expert, Voter = Value
  }
}
