package examples.hybrid.transaction

import examples.commons.SimpleBoxTransaction
import examples.curvepos.{Nonce, Value}
import scorex.core.ModifierTypeId
import scorex.core.transaction.Transaction
import scorex.core.transaction.box.proposition.{Proposition, PublicKey25519Proposition}
import scorex.core.transaction.proof.Signature25519

/**
  * A base class for all transactions related to treasury subsystem
  * @param signature signature with previously registered pub key. Treasury txs should be created only by registered entities (voters/experts/committee members)
  * @param timestamp
  */
abstract class TreasuryTransaction(/*signature: Signature25519,*/
                                   timestamp: Long)
  extends SimpleBoxTransaction(IndexedSeq(), IndexedSeq(), IndexedSeq(), 0L, timestamp) {

  val epochID: Long
}