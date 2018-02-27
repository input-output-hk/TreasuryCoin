package examples.commons

import com.google.common.primitives.{Bytes, Ints, Longs}
import examples.hybrid.transaction
import examples.hybrid.wallet.HWallet
import io.circe.Json
import io.circe.syntax._
import io.iohk.iodb.ByteArrayWrapper
import scorex.core.ModifierTypeId
import scorex.core.serialization.Serializer
import scorex.core.transaction.box.proposition.PublicKey25519Proposition
import scorex.core.transaction.proof.Signature25519
import scorex.core.transaction.state.{PrivateKey25519, PrivateKey25519Companion}
import scorex.crypto.encode.Base58
import scorex.crypto.signatures.{Curve25519, PublicKey, Signature}

import scala.util.Try

case class SimpleBoxTx(override val from: IndexedSeq[(PublicKey25519Proposition, Nonce)],
                       override val to: IndexedSeq[(PublicKey25519Proposition, Value)],
                       override val signatures: IndexedSeq[Signature25519],
                       override val fee: Long,
                       override val timestamp: Long) extends SimpleBoxTransaction(from, to, signatures, fee, timestamp) {

  override val transactionTypeId: ModifierTypeId = SimpleBoxTx.TransactionTypeId

  override type M = SimpleBoxTransaction
  override lazy val serializer = SimpleBoxTransactionCompanion

  override lazy val json: Json = Map(
    "id" -> Base58.encode(id).asJson,
    "newBoxes" -> newBoxes.map(b => Base58.encode(b.id).asJson).toSeq.asJson,
    "boxesToRemove" -> boxIdsToOpen.map(id => Base58.encode(id).asJson).asJson,
    "from" -> from.map { s =>
      Map(
        "proposition" -> Base58.encode(s._1.pubKeyBytes).asJson,
        "nonce" -> s._2.toLong.asJson
      ).asJson
    }.asJson,
    "to" -> to.map { s =>
      Map(
        "proposition" -> Base58.encode(s._1.pubKeyBytes).asJson,
        "value" -> s._2.toLong.asJson
      ).asJson
    }.asJson,
    "signatures" -> signatures.map(s => Base58.encode(s.signature).asJson).asJson,
    "fee" -> fee.asJson,
    "timestamp" -> timestamp.asJson
  ).asJson

  override def toString: String = s"SimpleBoxTx(${json.noSpaces})"

  lazy val semanticValidity: Try[Unit] = Try {
    require(from.size == signatures.size)
    require(to.forall(_._2 >= 0))
    require(fee >= 0)
    require(timestamp >= 0)
    require(boxIdsToOpen.map(to => ByteArrayWrapper(to)).distinct.size == boxIdsToOpen.size)
    require(from.zip(signatures).forall { case ((prop, _), proof) =>
      proof.isValid(prop, messageToSign)
    })
  }
}

object SimpleBoxTx {

  val TransactionTypeId: scorex.core.ModifierTypeId = scorex.core.ModifierTypeId @@ transaction.SimpleTxTypeId

  def apply(from: IndexedSeq[(PrivateKey25519, Nonce)],
            to: IndexedSeq[(PublicKey25519Proposition, Value)],
            fee: Long,
            timestamp: Long): SimpleBoxTx = {
    val fromPub = from.map { case (pr, n) => pr.publicImage -> n }
    val fakeSigs = from.map(_ => Signature25519(Signature @@ Array[Byte]()))

    val undersigned = SimpleBoxTx(fromPub, to, fakeSigs, fee, timestamp)

    val msg = undersigned.messageToSign
    val sigs = from.map { case (priv, _) => PrivateKey25519Companion.sign(priv, msg) }

    SimpleBoxTx(fromPub, to, sigs, fee, timestamp)
  }

  def create(w: HWallet,
             to: Seq[(PublicKey25519Proposition, Value)],
             fee: Long,
             boxesIdsToExclude: Seq[Array[Byte]] = Seq()): Try[SimpleBoxTx] = Try {
    var s = 0L
    val amount = to.map(_._2.toLong).sum

    val from: IndexedSeq[(PrivateKey25519, Nonce, Value)] = w.boxes()
      .filter(b => !boxesIdsToExclude.exists(_ sameElements b.box.id)).sortBy(_.createdAt).takeWhile { b =>
      s = s + b.box.value
      s < amount + b.box.value
    }.flatMap { b =>
      w.secretByPublicImage(b.box.proposition).map(s => (s, b.box.nonce, b.box.value))
    }.toIndexedSeq
    val canSend = from.map(_._3.toLong).sum
    val charge: (PublicKey25519Proposition, Value) = (w.publicKeys.head, Value @@ (canSend - amount - fee))

    val outputs: IndexedSeq[(PublicKey25519Proposition, Value)] = (to :+ charge).toIndexedSeq

    require(from.map(_._3.toLong).sum - outputs.map(_._2.toLong).sum == fee)

    val timestamp = System.currentTimeMillis()
    SimpleBoxTx(from.map(t => t._1 -> t._2), outputs, fee, timestamp)
  }
}


object SimpleBoxTxCompanion extends Serializer[SimpleBoxTransaction] {

  override def toBytes(m: SimpleBoxTransaction): Array[Byte] = {
    SimpleBoxTransactionCompanion.toBytesCommonArgs(m)
  }

  override def parseBytes(bytes: Array[Byte]): Try[SimpleBoxTransaction] = Try {
    val (from, to, signatures, fee, timestamp) = SimpleBoxTransactionCompanion.parseBytesCommonArgs(bytes).get
    new SimpleBoxTx(from, to, signatures, fee, timestamp)
  }
}
