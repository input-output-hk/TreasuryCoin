package examples.hybrid.transaction

import com.google.common.primitives.{Bytes, Ints, Longs}
import examples.commons._
import examples.hybrid.history.HybridHistory
import examples.hybrid.state.{HBoxStoredState, TreasuryState}
import io.circe.Json
import io.circe.syntax._
import io.iohk.iodb.ByteArrayWrapper
import scorex.core.ModifierTypeId
import scorex.core.serialization.Serializer
import scorex.core.transaction.box.proposition.{PublicKey25519Proposition, PublicKey25519PropositionSerializer}
import scorex.crypto.encode.Base58
import scorex.crypto.signatures.{Curve25519, PublicKey}

import scala.util.Try


case class PaymentTransaction(depositPayback: Seq[(PublicKey25519NoncedBox, PublicKey25519Proposition)],
                              coinbasePayments: Seq[(PublicKey25519Proposition, Value)],
                              override val epochID: Long,
                              override val timestamp: Long) extends TreasuryTransaction(timestamp = timestamp) {

  override type M = SimpleBoxTransaction

  override val transactionTypeId: ModifierTypeId = PaymentTransaction.TransactionTypeId

  override val serializer = SimpleBoxTransactionCompanion

  override val from = depositPayback.toIndexedSeq.map(p => (p._1.proposition, p._1.nonce))
  override val to = depositPayback.toIndexedSeq.map(p => (p._2, p._1.value)) ++ coinbasePayments

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

  def apply(depositPayback: Seq[(PublicKey25519NoncedBox, PublicKey25519Proposition)],
            coinbasePayments: Seq[(PublicKey25519Proposition, Value)],
            epochID: Long,
            timestamp: Long): PaymentTransaction = {

    new PaymentTransaction(depositPayback, coinbasePayments, epochID, timestamp)
  }

  def create(trState: TreasuryState, history: HybridHistory, state: HBoxStoredState): Try[PaymentTransaction] = Try {
    val timestamp = System.currentTimeMillis()

    val coinbasePayments = trState.getPayments.getOrElse(Seq()).toIndexedSeq
    val depositPaybacks = trState.getDepositPaybacks(history, state).getOrElse(Seq()).toIndexedSeq

    PaymentTransaction(depositPaybacks, coinbasePayments, trState.epochNum, timestamp)
  }
}

object PaymentTransactionCompanion extends Serializer[PaymentTransaction] {
  def toBytes(t: PaymentTransaction): Array[Byte] = {
    Bytes.concat(
      Longs.toByteArray(t.epochID),
      Longs.toByteArray(t.timestamp),
      Ints.toByteArray(t.depositPayback.length),
      t.depositPayback.foldLeft(Array[Byte]())((a, b) => Bytes.concat(a, b._1.bytes, b._2.bytes)),
      Ints.toByteArray(t.coinbasePayments.length),
      t.coinbasePayments.foldLeft(Array[Byte]())((a, b) => Bytes.concat(a, b._1.bytes, Longs.toByteArray(b._2)))
    )
  }

  def parseBytes(bytes: Array[Byte]): Try[PaymentTransaction] = Try {
    val epochID = Longs.fromByteArray(bytes.slice(0,8))
    val timestamp = Longs.fromByteArray(bytes.slice(8,16))

    val depositLength = Ints.fromByteArray(bytes.slice(16, 20))
    var pos = 20
    val deposits = (0 until depositLength) map { i =>
      val box = PublicKey25519NoncedBoxSerializer.parseBytes(bytes.slice(pos, pos + PublicKey25519NoncedBox.BoxLength)).get
      pos += PublicKey25519NoncedBox.BoxLength
      val propos = PublicKey25519PropositionSerializer.parseBytes(bytes.slice(pos, pos + PublicKey25519Proposition.PropositionLength)).get
      pos += PublicKey25519Proposition.PropositionLength
      (box, propos)
    }

    val paymentsLength = Ints.fromByteArray(bytes.slice(pos, pos+4))
    pos += 4
    val elementLength = 8 + Curve25519.KeyLength
    val payments = (0 until paymentsLength) map { i =>
      val propos = PublicKey25519PropositionSerializer.parseBytes(bytes.slice(pos, pos + PublicKey25519Proposition.PropositionLength)).get
      pos += PublicKey25519Proposition.PropositionLength
      val value = Longs.fromByteArray(bytes.slice(pos, pos+8))
      pos += 8
      (propos, Value @@ value)
    }

    PaymentTransaction(deposits, payments, epochID, timestamp)
  }
}
