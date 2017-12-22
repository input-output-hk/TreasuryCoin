package examples.hybrid.transaction

import examples.commons.SimpleBoxTransaction
import examples.curvepos.{Nonce, Value}
import scorex.core.ModifierTypeId
import scorex.core.transaction.Transaction
import scorex.core.transaction.box.proposition.{Proposition, PublicKey25519Proposition}
import scorex.core.transaction.proof.Signature25519

/**
  * A base class for all transactions related to treasury subsystem
  */
abstract class TreasuryTransaction(timestamp: Long)
  extends SimpleBoxTransaction(IndexedSeq(), IndexedSeq(), IndexedSeq(), 0L, timestamp) {

  val epochID: Long

  val blocksRangeToInclude: (Long, Long)

//  val depositBox: Box[P]

  val signature: Signature25519
}

/**
  * A base class for all registration transaction types in the Treasury system
  */
abstract class RegisterTTransaction(timestamp: Long) extends TreasuryTransaction(timestamp)