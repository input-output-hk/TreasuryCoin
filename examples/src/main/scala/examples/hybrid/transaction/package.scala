package examples.hybrid

package object transaction {

  val SimpleTxTypeId: scorex.core.ModifierTypeId = scorex.core.ModifierTypeId @@ 40.toByte

  /* Treasury transaction types. */
  val RegisterTxTypeId: scorex.core.ModifierTypeId = scorex.core.ModifierTypeId @@ 50.toByte
  val CommitteeRegisterTxTypeId: scorex.core.ModifierTypeId = scorex.core.ModifierTypeId @@ 51.toByte
  val BallotTxTypeId: scorex.core.ModifierTypeId = scorex.core.ModifierTypeId @@ 61.toByte
  val ProposalTxTypeId: scorex.core.ModifierTypeId = scorex.core.ModifierTypeId @@ 62.toByte
  val DecryptionShareTxTypeId: scorex.core.ModifierTypeId = scorex.core.ModifierTypeId @@ 63.toByte
  val PaymentTxTypeId: scorex.core.ModifierTypeId = scorex.core.ModifierTypeId @@ 64.toByte
}
