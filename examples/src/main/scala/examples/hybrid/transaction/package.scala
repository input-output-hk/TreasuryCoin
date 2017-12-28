package examples.hybrid

package object transaction {

  /* Treasury transaction types */
  val RegisterTxTypeId: scorex.core.ModifierTypeId = scorex.core.ModifierTypeId @@ 50.toByte

  val VoterBallotTxTypeId: scorex.core.ModifierTypeId = scorex.core.ModifierTypeId @@ 51.toByte
}
