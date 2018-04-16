package examples.hybrid.transaction.mandatory

import com.google.common.primitives.{Bytes, Ints, Longs}
import examples.commons._
import examples.hybrid.history.HybridHistory
import examples.hybrid.state.{HBoxStoredState, TreasuryState}
import examples.hybrid.transaction.{PenaltyTxTypeId, TreasuryTransaction}
import io.circe.Json
import io.circe.syntax._
import io.iohk.iodb.ByteArrayWrapper
import scorex.core.ModifierTypeId
import scorex.core.serialization.Serializer
import scorex.crypto.encode.Base58

import scala.util.Try


case class PenaltyTransaction(depositsToDestroy: Seq[PublicKey25519NoncedBox],
                              override val epochID: Long,
                              override val timestamp: Long) extends TreasuryTransaction(timestamp = timestamp) {

  override type M = SimpleBoxTransaction

  override val transactionTypeId: ModifierTypeId = PenaltyTransaction.TransactionTypeId

  override val serializer = SimpleBoxTransactionCompanion

  override val from = depositsToDestroy.toIndexedSeq.map(p => (p.proposition, p.nonce))
  override val to = IndexedSeq()

  override lazy val messageToSign = {
    val superBytes = Bytes.concat(if (newBoxes.nonEmpty) scorex.core.utils.concatBytes(newBoxes.map(_.bytes)) else Array[Byte](),
      scorex.core.utils.concatFixLengthBytes(unlockers.map(_.closedBoxId)),
      Longs.toByteArray(timestamp),
      Longs.toByteArray(fee))

    val depositsBytes = depositsToDestroy.foldLeft(Array[Byte]()) { (acc, d) =>
      Bytes.concat(acc, d.bytes)
    }

    Bytes.concat(depositsBytes, Longs.toByteArray(epochID), superBytes)
  }

  override lazy val json: Json = Map(
    "id" -> Base58.encode(id).asJson,
    "depositsToDestroy" -> depositsToDestroy.map { s =>
      Map(
        "proposition" -> Base58.encode(s.proposition.pubKeyBytes).asJson,
        "value" -> s.value.toLong.asJson
      ).asJson
    }.asJson,
    "timestamp" -> timestamp.asJson
  ).asJson

  lazy val semanticValidity: Try[Unit] = Try {
    require(signatures.size == 0)
    require(to.size == 0)
    require(fee == 0)
    require(timestamp >= 0)
    require(depositsToDestroy.map(d => ByteArrayWrapper(d.bytes)).distinct.size == depositsToDestroy.size)
  }

  override def toString: String = s"PenaltyTransaction(${json.noSpaces})"
}

object PenaltyTransaction {
  val TransactionTypeId: scorex.core.ModifierTypeId = PenaltyTxTypeId

  def apply(depositsToDestroy: Seq[PublicKey25519NoncedBox],
            epochID: Long,
            timestamp: Long): PenaltyTransaction = {

    new PenaltyTransaction(depositsToDestroy, epochID, timestamp)
  }

  def create(trState: TreasuryState, history: HybridHistory, state: HBoxStoredState): Try[PenaltyTransaction] = Try {
    val timestamp = System.currentTimeMillis()

    val depositsToDestroy = trState.getPenalties.toIndexedSeq

    PenaltyTransaction(depositsToDestroy, trState.epochNum, timestamp)
  }
}

object PenaltyTransactionCompanion extends Serializer[PenaltyTransaction] {
  def toBytes(t: PenaltyTransaction): Array[Byte] = {
    Bytes.concat(
      Longs.toByteArray(t.epochID),
      Longs.toByteArray(t.timestamp),
      Ints.toByteArray(t.depositsToDestroy.length),
      t.depositsToDestroy.foldLeft(Array[Byte]())((a, b) => Bytes.concat(a, b.bytes)),
    )
  }

  def parseBytes(bytes: Array[Byte]): Try[PenaltyTransaction] = Try {
    val epochID = Longs.fromByteArray(bytes.slice(0,8))
    val timestamp = Longs.fromByteArray(bytes.slice(8,16))

    val depositLength = Ints.fromByteArray(bytes.slice(16, 20))
    var pos = 20
    val depositsToDestroy = (0 until depositLength) map { i =>
      val box = PublicKey25519NoncedBoxSerializer.parseBytes(bytes.slice(pos, pos + PublicKey25519NoncedBox.BoxLength)).get
      pos += PublicKey25519NoncedBox.BoxLength
      box
    }

    PenaltyTransaction(depositsToDestroy, epochID, timestamp)
  }
}
