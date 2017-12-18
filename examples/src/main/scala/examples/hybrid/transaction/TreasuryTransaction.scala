package examples.hybrid.transaction

import scorex.core.ModifierTypeId
import scorex.core.transaction.Transaction
import scorex.core.transaction.box.proposition.{Proposition, PublicKey25519Proposition}
import scorex.core.transaction.proof.Signature25519


/**
  * A base class for all treasury transactions
  * @tparam P
  */
abstract class TreasuryTransaction[P <: Proposition] extends Transaction[P] {
  override val modifierTypeId: ModifierTypeId = TreasuryTransaction.ModifierTypeId

  val epochID: Long

  val blocksRangeToInclude: (Long, Long)

//  val depositBox: Box[P]

  val signature: Signature25519
}

object TreasuryTransaction {
  val ModifierTypeId: scorex.core.ModifierTypeId = scorex.core.ModifierTypeId @@ 21.toByte
}

/**
  * A base class for all registration transaction types in the Treasury system
  */
abstract class RegisterTTransaction extends TreasuryTransaction[PublicKey25519Proposition]