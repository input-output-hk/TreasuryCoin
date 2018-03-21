package examples.hybrid

package object transaction {

  val SimpleTxTypeId: scorex.core.ModifierTypeId = scorex.core.ModifierTypeId @@ 40.toByte

  /* Treasury transaction types. */
  val RegisterTxTypeId: scorex.core.ModifierTypeId = scorex.core.ModifierTypeId @@ 50.toByte
  val CommitteeRegisterTxTypeId: scorex.core.ModifierTypeId = scorex.core.ModifierTypeId @@ 51.toByte
  val BallotTxTypeId: scorex.core.ModifierTypeId = scorex.core.ModifierTypeId @@ 61.toByte
  val ProposalTxTypeId: scorex.core.ModifierTypeId = scorex.core.ModifierTypeId @@ 62.toByte
  val DecryptionShareTxTypeId: scorex.core.ModifierTypeId = scorex.core.ModifierTypeId @@ 63.toByte
  val RecoveryShareTxTypeId: scorex.core.ModifierTypeId = scorex.core.ModifierTypeId @@ 64.toByte
  val DKGr1TxTypeId: scorex.core.ModifierTypeId = scorex.core.ModifierTypeId @@ 65.toByte
  val DKGr2TxTypeId: scorex.core.ModifierTypeId = scorex.core.ModifierTypeId @@ 66.toByte
  val DKGr3TxTypeId: scorex.core.ModifierTypeId = scorex.core.ModifierTypeId @@ 67.toByte
  val DKGr4TxTypeId: scorex.core.ModifierTypeId = scorex.core.ModifierTypeId @@ 68.toByte
  val DKGr5TxTypeId: scorex.core.ModifierTypeId = scorex.core.ModifierTypeId @@ 69.toByte
  val DKGr6TxTypeId: scorex.core.ModifierTypeId = scorex.core.ModifierTypeId @@ 70.toByte
  val PaymentTxTypeId: scorex.core.ModifierTypeId = scorex.core.ModifierTypeId @@ 71.toByte
  val RandomnessTxTypeId: scorex.core.ModifierTypeId = scorex.core.ModifierTypeId @@ 72.toByte
  val RandomnessDecryptionTxTypeId: scorex.core.ModifierTypeId = scorex.core.ModifierTypeId @@ 73.toByte
}
