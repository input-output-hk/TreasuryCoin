package examples.commons

import com.google.common.primitives.{Bytes, Ints, Longs}
import examples.commons.SimpleBoxTransaction._
import examples.hybrid.transaction._
import examples.hybrid.wallet.HWallet
import io.circe.Json
import io.circe.syntax._
import io.iohk.iodb.ByteArrayWrapper
import scorex.core.{ModifierId, ModifierTypeId}
import scorex.core.serialization.Serializer
import scorex.core.transaction.{BoxTransaction, Transaction}
import scorex.core.transaction.account.PublicKeyNoncedBox
import scorex.core.transaction.box.BoxUnlocker
import scorex.core.transaction.box.proposition.PublicKey25519Proposition
import scorex.core.transaction.proof.{Proof, Signature25519}
import scorex.crypto.hash.Blake2b256

import scala.util.{Failure, Try}

//A transaction orders to destroy boxes associated with (pubkey -> nonce) and create new boxes (pubkey -> nonce)
// where a nonce is derived from a transaction and also a box index

// WARNING!: the scheme is not provably secure to replay attacks etc

// It is an abstract class which is a parent of both Simple transactions and Treasury transactions
abstract class SimpleBoxTransaction(val from: IndexedSeq[(PublicKey25519Proposition, Nonce)],
                                    val to: IndexedSeq[(PublicKey25519Proposition, Value)],
                                    val signatures: IndexedSeq[Signature25519],
                                    override val fee: Long,
                                    override val timestamp: Long)
  extends BoxTransaction[PublicKey25519Proposition, PublicKey25519NoncedBox] {

  val transactionTypeId: ModifierTypeId

  lazy val boxIdsToOpen: IndexedSeq[ModifierId] = from.map { case (prop, nonce) =>
    PublicKeyNoncedBox.idFromBox(prop, nonce)
  }

  override lazy val unlockers: Traversable[BoxUnlocker[PublicKey25519Proposition]] = boxIdsToOpen.zip(signatures).map {
    case (boxId, signature) =>
      new BoxUnlocker[PublicKey25519Proposition] {
        override val closedBoxId: ModifierId = boxId
        override val boxKey: Proof[PublicKey25519Proposition] = signature
      }
  }

  lazy val hashNoNonces = Blake2b256(
    Bytes.concat(scorex.core.utils.concatFixLengthBytes(to.map(_._1.pubKeyBytes)),
      scorex.core.utils.concatFixLengthBytes(unlockers.map(_.closedBoxId)),
      Longs.toByteArray(timestamp),
      Longs.toByteArray(fee))
  )

  override lazy val newBoxes: Traversable[PublicKey25519NoncedBox] = to.zipWithIndex.map { case ((prop, value), idx) =>
    val nonce = SimpleBoxTransaction.nonceFromDigest(Blake2b256(prop.pubKeyBytes ++ hashNoNonces ++ Ints.toByteArray(idx)))
    PublicKey25519NoncedBox(prop, nonce, value)
  }

  val semanticValidity: Try[Unit]
}

object SimpleBoxTransaction {

  def nonceFromDigest(digest: Array[Byte]): Nonce = Nonce @@ Longs.fromByteArray(digest.take(8))
}

object SimpleBoxTransactionCompanion extends Serializer[SimpleBoxTransaction] {

  override def toBytes(m: SimpleBoxTransaction): Array[Byte] = {
    m match {
      case t: SimpleBoxTx => Bytes.concat(Array(m.transactionTypeId), SimpleBoxTxCompanion.toBytes(t))
      case t: RegisterTransaction => Bytes.concat(Array(m.transactionTypeId), RegisterTransactionCompanion.toBytes(t))
      case t: CommitteeRegisterTransaction => Bytes.concat(Array(m.transactionTypeId), CommitteeRegisterTransactionCompanion.toBytes(t))
      case t: ProposalTransaction => Bytes.concat(Array(m.transactionTypeId), ProposalTransactionCompanion.toBytes(t))
      case t: BallotTransaction => Bytes.concat(Array(m.transactionTypeId), BallotTransactionCompanion.toBytes(t))
    }
  }

  override def parseBytes(bytes: Array[Byte]): Try[SimpleBoxTransaction] = {
    val transactionTypeId = ModifierTypeId @@ bytes(0)
    transactionTypeId match {
      case SimpleBoxTx.TransactionTypeId => SimpleBoxTxCompanion.parseBytes(bytes.drop(1))
      case RegisterTransaction.TransactionTypeId => RegisterTransactionCompanion.parseBytes(bytes.drop(1))
      case CommitteeRegisterTransaction.TransactionTypeId => CommitteeRegisterTransactionCompanion.parseBytes(bytes.drop(1))
      case ProposalTransaction.TransactionTypeId => ProposalTransactionCompanion.parseBytes(bytes.drop(1))
      case BallotTransaction.TransactionTypeId => BallotTransactionCompanion.parseBytes(bytes.drop(1))
      case _ => Failure(new MatchError("Unknown transaction type id"))
    }
  }
}