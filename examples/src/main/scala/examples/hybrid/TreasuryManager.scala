package examples.hybrid

import scorex.core.transaction.box.proposition.PublicKey25519Proposition
import scorex.crypto.signatures.{Curve25519, PublicKey}
import treasury.crypto.core.Cryptosystem

object TreasuryManager {

  val cs = new Cryptosystem

  /* Intervals of an epoch stages in blocks (both Pos/Pow). All numbers should be even. */
  val EPOCH_LEN =                             780
  val PROPOSAL_SUBMISSION_RANGE =             10 until 70
  val VOTER_REGISTER_RANGE =                  10 until 60
  val EXPERT_REGISTER_RANGE =                 60 until 110
  val RANDOMNESS_DECRYPTION_RANGE =           110 until 160
  val RANDOMNESS_DECRYPTION_RECOVERY_RANGE =  160 until 210
  val RANDOMNESS_BLOCK_HEIGHT =               210
  val DISTR_KEY_GEN_R1_RANGE =                212 until 260
  val DISTR_KEY_GEN_R2_RANGE =                260 until 310
  val DISTR_KEY_GEN_R3_RANGE =                310 until 360
  val DISTR_KEY_GEN_R4_RANGE =                360 until 410
  val DISTR_KEY_GEN_R5_RANGE =                410 until 460
  val VOTING_RANGE =                          460 until 510
  val VOTING_DECRYPTION_R1_RANGE =            510 until 560
  val VOTING_DECRYPTION_R1_RECOVERY_RANGE =   560 until 610
  val VOTING_DECRYPTION_R2_RANGE =            610 until 660
  val VOTING_DECRYPTION_R2_RECOVERY_RANGE =   660 until 710
  val RANDOMNESS_SUBMISSION_RANGE =           710 until 760
  val PENALTY_BLOCK_HEIGHT =                  764
  val PAYMENT_BLOCK_HEIGHT =                  768

//  val EPOCH_LEN =                             188
//  val PROPOSAL_SUBMISSION_RANGE =             4 until 20
//  val VOTER_REGISTER_RANGE =                  4 until 14
//  val EXPERT_REGISTER_RANGE =                 14 until 24
//  val RANDOMNESS_DECRYPTION_RANGE =           24 until 34
//  val RANDOMNESS_DECRYPTION_RECOVERY_RANGE =  34 until 44
//  val RANDOMNESS_BLOCK_HEIGHT =               44
//  val DISTR_KEY_GEN_R1_RANGE =                46 until 58
//  val DISTR_KEY_GEN_R2_RANGE =                58 until 70
//  val DISTR_KEY_GEN_R3_RANGE =                70 until 82
//  val DISTR_KEY_GEN_R4_RANGE =                82 until 94
//  val DISTR_KEY_GEN_R5_RANGE =                94 until 106
//  val VOTING_RANGE =                          106 until 122
//  val VOTING_DECRYPTION_R1_RANGE =            122 until 134
//  val VOTING_DECRYPTION_R1_RECOVERY_RANGE =   134 until 146
//  val VOTING_DECRYPTION_R2_RANGE =            146 until 158
//  val VOTING_DECRYPTION_R2_RECOVERY_RANGE =   158 until 170
//  val RANDOMNESS_SUBMISSION_RANGE =           170 until 182
//  val PENALTY_BLOCK_HEIGHT =                  184
//  val PAYMENT_BLOCK_HEIGHT =                  186

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
