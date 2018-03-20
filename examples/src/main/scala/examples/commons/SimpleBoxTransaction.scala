package examples.commons

import com.google.common.primitives.{Bytes, Ints, Longs}
import examples.commons.SimpleBoxTransaction._
import examples.hybrid.transaction.DKG._
import examples.hybrid.transaction._
import examples.hybrid.wallet.HWallet
import io.circe.{Encoder, Json}
import io.circe.syntax._
import io.iohk.iodb.ByteArrayWrapper
import scorex.core.{ModifierId, ModifierTypeId}
import scorex.core.serialization.Serializer
import scorex.core.transaction.{BoxTransaction, Transaction}
import scorex.core.transaction.account.PublicKeyNoncedBox
import scorex.core.transaction.box.BoxUnlocker
import scorex.core.transaction.box.proposition.PublicKey25519Proposition
import scorex.core.transaction.proof.{Proof, Signature25519}
import scorex.crypto.encode.Base58
import scorex.crypto.hash.Blake2b256
import scorex.crypto.signatures.{Curve25519, PublicKey, Signature}

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

  val json: Json

  val semanticValidity: Try[Unit]
}

object SimpleBoxTransaction {

  type Arguments = (
      IndexedSeq[(PublicKey25519Proposition, Nonce)], // from
      IndexedSeq[(PublicKey25519Proposition, Value)], // to
      IndexedSeq[Signature25519], // signatures
      Long, // fee
      Long) // timestamp

  implicit val simpleBoxEncoder: Encoder[SimpleBoxTransaction] = (sbe: SimpleBoxTransaction) => sbe.json

  def nonceFromDigest(digest: Array[Byte]): Nonce = Nonce @@ Longs.fromByteArray(digest.take(8))
}

object SimpleBoxTransactionCompanion extends Serializer[SimpleBoxTransaction] {

  override def toBytes(m: SimpleBoxTransaction): Array[Byte] = {
    m match {
      case t: SimpleBoxTx => Bytes.concat(Array(m.transactionTypeId), SimpleBoxTxCompanion.toBytes(t))
      case t: RegisterTransaction => Bytes.concat(Array(m.transactionTypeId), RegisterTransactionCompanion.toBytes(t))
      case t: ProposalTransaction => Bytes.concat(Array(m.transactionTypeId), ProposalTransactionCompanion.toBytes(t))
      case t: BallotTransaction => Bytes.concat(Array(m.transactionTypeId), BallotTransactionCompanion.toBytes(t))
      case t: DecryptionShareTransaction => Bytes.concat(Array(m.transactionTypeId), DecryptionShareTransactionCompanion.toBytes(t))
      case t: RecoveryShareTransaction => Bytes.concat(Array(m.transactionTypeId), RecoveryShareTransactionCompanion.toBytes(t))
      case t: PaymentTransaction => Bytes.concat(Array(m.transactionTypeId), PaymentTransactionCompanion.toBytes(t))
      case t: DKGr1Transaction => Bytes.concat(Array(m.transactionTypeId), DKGr1TransactionCompanion.toBytes(t))
      case t: DKGr2Transaction => Bytes.concat(Array(m.transactionTypeId), DKGr2TransactionCompanion.toBytes(t))
      case t: DKGr3Transaction => Bytes.concat(Array(m.transactionTypeId), DKGr3TransactionCompanion.toBytes(t))
      case t: DKGr4Transaction => Bytes.concat(Array(m.transactionTypeId), DKGr4TransactionCompanion.toBytes(t))
      case t: DKGr5Transaction => Bytes.concat(Array(m.transactionTypeId), DKGr5TransactionCompanion.toBytes(t))
      case t: SeedTransaction => Bytes.concat(Array(m.transactionTypeId), SeedTransactionCompanion.toBytes(t))
    }
  }

  override def parseBytes(bytes: Array[Byte]): Try[SimpleBoxTransaction] = {
    val transactionTypeId = ModifierTypeId @@ bytes(0)
    transactionTypeId match {
      case SimpleBoxTx.TransactionTypeId => SimpleBoxTxCompanion.parseBytes(bytes.drop(1))
      case RegisterTransaction.TransactionTypeId => RegisterTransactionCompanion.parseBytes(bytes.drop(1))
      case ProposalTransaction.TransactionTypeId => ProposalTransactionCompanion.parseBytes(bytes.drop(1))
      case BallotTransaction.TransactionTypeId => BallotTransactionCompanion.parseBytes(bytes.drop(1))
      case DecryptionShareTransaction.TransactionTypeId => DecryptionShareTransactionCompanion.parseBytes(bytes.drop(1))
      case RecoveryShareTransaction.TransactionTypeId => RecoveryShareTransactionCompanion.parseBytes(bytes.drop(1))
      case PaymentTransaction.TransactionTypeId => PaymentTransactionCompanion.parseBytes(bytes.drop(1))
      case DKGr1Transaction.TransactionTypeId => DKGr1TransactionCompanion.parseBytes(bytes.drop(1))
      case DKGr2Transaction.TransactionTypeId => DKGr2TransactionCompanion.parseBytes(bytes.drop(1))
      case DKGr3Transaction.TransactionTypeId => DKGr3TransactionCompanion.parseBytes(bytes.drop(1))
      case DKGr4Transaction.TransactionTypeId => DKGr4TransactionCompanion.parseBytes(bytes.drop(1))
      case DKGr5Transaction.TransactionTypeId => DKGr5TransactionCompanion.parseBytes(bytes.drop(1))
      case SeedTransaction.TransactionTypeId => SeedTransactionCompanion.parseBytes(bytes.drop(1))
      case _ => Failure(new MatchError("Unknown transaction type id"))
    }
  }

  def toBytesCommonArgs(m: SimpleBoxTransaction): Array[Byte] = {
    Bytes.concat(Longs.toByteArray(m.fee),
      Longs.toByteArray(m.timestamp),
      Ints.toByteArray(m.signatures.length),
      Ints.toByteArray(m.from.length),
      Ints.toByteArray(m.to.length),
      m.signatures.foldLeft(Array[Byte]())((a, b) => Bytes.concat(a, b.bytes)),
      m.from.foldLeft(Array[Byte]())((a, b) => Bytes.concat(a, b._1.bytes, Longs.toByteArray(b._2))),
      m.to.foldLeft(Array[Byte]())((a, b) => Bytes.concat(a, b._1.bytes, Longs.toByteArray(b._2)))
    )
  }

  def parseBytesCommonArgs(bytes: Array[Byte]): Try[Arguments] = Try {
    val fee = Longs.fromByteArray(bytes.slice(0, 8))
    val timestamp = Longs.fromByteArray(bytes.slice(8, 16))
    val sigLength = Ints.fromByteArray(bytes.slice(16, 20))
    val fromLength = Ints.fromByteArray(bytes.slice(20, 24))
    val toLength = Ints.fromByteArray(bytes.slice(24, 28))
    val signatures = (0 until sigLength) map { i =>
      Signature25519(Signature @@ bytes.slice(28 + i * Curve25519.SignatureLength, 28 + (i + 1) * Curve25519.SignatureLength))
    }
    val s = 28 + sigLength * Curve25519.SignatureLength
    val elementLength = 8 + Curve25519.KeyLength
    val from = (0 until fromLength) map { i =>
      val pk = PublicKey @@ bytes.slice(s + i * elementLength, s + (i + 1) * elementLength - 8)
      val v = Longs.fromByteArray(bytes.slice(s + (i + 1) * elementLength - 8, s + (i + 1) * elementLength))
      (PublicKey25519Proposition(pk), Nonce @@ v)
    }
    val s2 = s + fromLength * elementLength
    val to = (0 until toLength) map { i =>
      val pk = PublicKey @@ bytes.slice(s2 + i * elementLength, s2 + (i + 1) * elementLength - 8)
      val v = Longs.fromByteArray(bytes.slice(s2 + (i + 1) * elementLength - 8, s2 + (i + 1) * elementLength))
      (PublicKey25519Proposition(pk), Value @@ v)
    }

    (from, to, signatures, fee, timestamp)
  }
}