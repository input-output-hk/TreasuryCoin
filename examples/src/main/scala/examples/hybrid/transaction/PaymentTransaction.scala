package examples.hybrid.transaction

import com.google.common.primitives.{Bytes, Ints, Longs}
import examples.commons.{SimpleBoxTransaction, SimpleBoxTransactionCompanion, Value}
import examples.hybrid.state.TreasuryState
import io.circe.Json
import io.circe.syntax._
import io.iohk.iodb.ByteArrayWrapper
import scorex.core.ModifierTypeId
import scorex.core.serialization.Serializer
import scorex.core.transaction.box.proposition.PublicKey25519Proposition
import scorex.crypto.encode.Base58
import scorex.crypto.signatures.{Curve25519, PublicKey}

import scala.util.Try


case class PaymentTransaction(override val epochID: Long,
                              override val to: IndexedSeq[(PublicKey25519Proposition, Value)],
                              override val timestamp: Long) extends TreasuryTransaction(timestamp = timestamp) {

  override type M = SimpleBoxTransaction

  override val transactionTypeId: ModifierTypeId = PaymentTransaction.TransactionTypeId

  override val serializer = SimpleBoxTransactionCompanion

  override lazy val messageToSign = {
    val superBytes = Bytes.concat(if (newBoxes.nonEmpty) scorex.core.utils.concatBytes(newBoxes.map(_.bytes)) else Array[Byte](),
      scorex.core.utils.concatFixLengthBytes(unlockers.map(_.closedBoxId)),
      Longs.toByteArray(timestamp),
      Longs.toByteArray(fee))

    Bytes.concat(Longs.toByteArray(epochID), superBytes)
  }

  override lazy val json: Json = Map(
    "id" -> Base58.encode(id).asJson,
    "newBoxes" -> newBoxes.map(b => Base58.encode(b.id).asJson).toSeq.asJson,
    "to" -> to.map { s =>
      Map(
        "proposition" -> Base58.encode(s._1.pubKeyBytes).asJson,
        "value" -> s._2.toLong.asJson
      ).asJson
    }.asJson,
    "timestamp" -> timestamp.asJson
  ).asJson

  lazy val semanticValidity: Try[Unit] = Try {
    require(from.size == 0)
    require(signatures.size == 0)
    require(to.forall(_._2 >= 0))
    require(fee == 0)
    require(timestamp >= 0)
    require(boxIdsToOpen.map(to => ByteArrayWrapper(to)).distinct.size == boxIdsToOpen.size)
  }

  override def toString: String = s"PaymentTransaction(${json.noSpaces})"
}

object PaymentTransaction {
  val TransactionTypeId: scorex.core.ModifierTypeId = PaymentTxTypeId

  def apply(to: IndexedSeq[(PublicKey25519Proposition, Value)],
            epochID: Long,
            timestamp: Long): PaymentTransaction = {

    new PaymentTransaction(epochID, to, timestamp)
  }

  def create(state: TreasuryState): Try[PaymentTransaction] = Try {
    val timestamp = System.currentTimeMillis()

    val to = state.getPayments.getOrElse(Seq()).toIndexedSeq

    PaymentTransaction(state.epochNum, to, timestamp)
  }
}

object PaymentTransactionCompanion extends Serializer[PaymentTransaction] {
  def toBytes(t: PaymentTransaction): Array[Byte] = {
    Bytes.concat(
      Longs.toByteArray(t.epochID),
      Longs.toByteArray(t.timestamp),
      Ints.toByteArray(t.to.length),
      t.to.foldLeft(Array[Byte]())((a, b) => Bytes.concat(a, b._1.bytes, Longs.toByteArray(b._2)))
    )
  }

  def parseBytes(bytes: Array[Byte]): Try[PaymentTransaction] = Try {
    val epochID = Longs.fromByteArray(bytes.slice(0,8))
    val timestamp = Longs.fromByteArray(bytes.slice(8,16))
    val toLength = Ints.fromByteArray(bytes.slice(16, 20))

    val elementLength = 8 + Curve25519.KeyLength
    val pos = 20
    val to = (0 until toLength) map { i =>
      val pk = PublicKey @@ bytes.slice(pos + i * elementLength, pos + (i + 1) * elementLength - 8)
      val v = Longs.fromByteArray(bytes.slice(pos + (i + 1) * elementLength - 8, pos + (i + 1) * elementLength))
      (PublicKey25519Proposition(pk), Value @@ v)
    }

    PaymentTransaction(epochID, to, timestamp)
  }
}
