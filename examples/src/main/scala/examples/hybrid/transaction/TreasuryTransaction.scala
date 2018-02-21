package examples.hybrid.transaction

import examples.commons.{Nonce, SimpleBoxTransaction, Value}
import scorex.core.transaction.box.proposition.{Proposition, PublicKey25519Proposition}
import scorex.core.transaction.proof.Signature25519

/**
  * A base class for all transactions related to treasury subsystem
  */
abstract class TreasuryTransaction(from: IndexedSeq[(PublicKey25519Proposition, Nonce)] = IndexedSeq(),
                                   to: IndexedSeq[(PublicKey25519Proposition, Value)] = IndexedSeq(),
                                   signatures: IndexedSeq[Signature25519] = IndexedSeq(),
                                   fee: Long = 0L,
                                   timestamp: Long)
  extends SimpleBoxTransaction(from, to, signatures, fee, timestamp) {

  def epochID: Long
}

/**
  *  A base class for all treasury transactions that should be signed by a previously registered key (RegisterTransaction, BallotTransaction, etc.)
  *    pubKey - previously registered public key that identifies a creator of a transaction
  *    signature - signature of the transaction that has been made with pubKey
  */
abstract class SignedTreasuryTransaction(time: Long) extends TreasuryTransaction(timestamp = time) {

  def pubKey: PublicKey25519Proposition
  def signature: Signature25519
}