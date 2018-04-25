package examples.hybrid

import scorex.core.transaction.box.proposition.PublicKey25519Proposition
import scorex.crypto.signatures.{Curve25519, PublicKey}
import treasury.crypto.core.Cryptosystem

object TreasuryManager {

  val cs: Cryptosystem = new Cryptosystem

  /* Intervals of an epoch stages in blocks (both Pos/Pow). All numbers should be even. */
//  val EPOCH_LEN: Int =                               780
//  val PROPOSAL_SUBMISSION_RANGE: Range =             10 until 70
//  val VOTER_REGISTER_RANGE: Range =                  10 until 60
//  val EXPERT_REGISTER_RANGE: Range =                 60 until 110
//  val RANDOMNESS_DECRYPTION_RANGE: Range =           110 until 160
//  val RANDOMNESS_DECRYPTION_RECOVERY_RANGE: Range =  160 until 210
//  val RANDOMNESS_BLOCK_HEIGHT: Int =                 212
//  val DISTR_KEY_GEN_R1_RANGE: Range =                214 until 260
//  val DISTR_KEY_GEN_R2_RANGE: Range =                260 until 310
//  val DISTR_KEY_GEN_R3_RANGE: Range =                310 until 360
//  val DISTR_KEY_GEN_R4_RANGE: Range =                360 until 410
//  val DISTR_KEY_GEN_R5_RANGE: Range =                410 until 460
//  val VOTING_RANGE: Range =                          460 until 510
//  val VOTING_DECRYPTION_R1_RANGE: Range =            510 until 560
//  val VOTING_DECRYPTION_R1_RECOVERY_RANGE: Range =   560 until 610
//  val VOTING_DECRYPTION_R2_RANGE: Range =            610 until 660
//  val VOTING_DECRYPTION_R2_RECOVERY_RANGE: Range =   660 until 710
//  val RANDOMNESS_SUBMISSION_RANGE: Range =           710 until 760
//  val PENALTY_BLOCK_HEIGHT: Int =                    764
//  val PAYMENT_BLOCK_HEIGHT: Int =                    768

  val EPOCH_LEN: Int =                               190
  val PROPOSAL_SUBMISSION_RANGE: Range =             4 until 20
  val VOTER_REGISTER_RANGE: Range =                  4 until 14
  val EXPERT_REGISTER_RANGE: Range =                 14 until 24
  val RANDOMNESS_DECRYPTION_RANGE: Range =           24 until 34
  val RANDOMNESS_DECRYPTION_RECOVERY_RANGE: Range =  34 until 44
  val RANDOMNESS_BLOCK_HEIGHT: Int   =               46
  val DISTR_KEY_GEN_R1_RANGE: Range =                48 until 60
  val DISTR_KEY_GEN_R2_RANGE: Range =                60 until 72
  val DISTR_KEY_GEN_R3_RANGE: Range =                72 until 84
  val DISTR_KEY_GEN_R4_RANGE: Range =                84 until 96
  val DISTR_KEY_GEN_R5_RANGE: Range =                96 until 108
  val VOTING_RANGE: Range =                          108 until 124
  val VOTING_DECRYPTION_R1_RANGE: Range =            124 until 136
  val VOTING_DECRYPTION_R1_RECOVERY_RANGE: Range =   136 until 148
  val VOTING_DECRYPTION_R2_RANGE: Range =            148 until 160
  val VOTING_DECRYPTION_R2_RECOVERY_RANGE: Range =   160 until 172
  val RANDOMNESS_SUBMISSION_RANGE: Range =           172 until 184
  val PENALTY_BLOCK_HEIGHT: Int   =                  186
  val PAYMENT_BLOCK_HEIGHT: Int   =                  188

  /* Constants related to reward distribution */
  val BUDGET: Int =               1000
  val PROPOSALS_BUDGET: Double =  0.7 * BUDGET
  val VOTERS_BUDGET: Double =     0.1 * BUDGET
  val COMMITTEE_BUDGET: Double =  0.1 * BUDGET
  val EXPERTS_BUDGET: Double =    0.1 * BUDGET

  /* Constants related to deposits */
  val VOTER_DEPOSIT_RANGE: Range = 10 to 1000
  val EXPERT_DEPOSIT_RANGE: Range = 100 to 100 // fixed deposit
  val COMMITTEE_DEPOSIT_RANGE: Range = 100 to 100
  val DEPOSIT_LOCK_PERIOD: Int = 1 // should be at least 1 otherwise RandGen penalties should be disabled (cause they are possible only in the next epoch)
  val VOTER_DEPOSIT_ADDR: PublicKey25519Proposition = PublicKey25519Proposition(PublicKey @@ Array.fill[Byte](Curve25519.KeyLength)(0.toByte)) // actually it's a proof of burn address
  val COMMITTEE_DEPOSIT_ADDR: PublicKey25519Proposition = PublicKey25519Proposition(PublicKey @@ Array.fill[Byte](Curve25519.KeyLength)(1.toByte)) // actually it's a proof of burn address

  /* How much committee members are allowed in a single epoch */
  val COMMITTEE_SIZE: Int = 10

  object Role extends Enumeration {
    type Role = Value
    val Committee, Expert, Voter: Role = Value
  }
}
