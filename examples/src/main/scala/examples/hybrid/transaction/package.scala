package examples.hybrid

package object transaction {

  /* Treasury transaction types */
  val CommitteeRegisterTxTypeId: scorex.core.ModifierTypeId = scorex.core.ModifierTypeId @@ 50.toByte

  val VoterRegisterTxTypeId: scorex.core.ModifierTypeId = scorex.core.ModifierTypeId @@ 51.toByte

  val ExpertRegisterTxTypeId: scorex.core.ModifierTypeId = scorex.core.ModifierTypeId @@ 52.toByte

  val VoterBallotTxTypeId: scorex.core.ModifierTypeId = scorex.core.ModifierTypeId @@ 53.toByte
}
