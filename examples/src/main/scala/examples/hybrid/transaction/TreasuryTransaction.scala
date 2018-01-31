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

  def epochID: Long
}

/**
  *  A base class for all treasury transactions that should be signed by a previously registered key (RegisterTransaction, BallotTransaction, etc.)
  *    pubKey - previously registered public key that identifies a creator of a transaction
  *    signature - signature of the transaction that has been made with pubKey
  */
abstract class SignedTreasuryTransaction(timestamp: Long) extends TreasuryTransaction(timestamp) {

  def pubKey: PublicKey25519Proposition
  def signature: Signature25519
}