package examples.hybrid.transaction.mandatory

import com.google.common.primitives.{Bytes, Ints, Longs}
import examples.commons._
import examples.hybrid.state.TreasuryState
import examples.hybrid.transaction.{RandomnessTxTypeId, TreasuryTransaction}
import io.circe.Json
import io.circe.syntax._
import scorex.core.ModifierTypeId
import scorex.core.serialization.Serializer
import scorex.crypto.encode.Base58

import scala.util.Try

/**
  * TODO: Actually there is no strict necessety in this transaction. The only reason we have it because we want to extract
  * randomness in fast and easy way. Fixing it in a blockchain at particular height is easy
  * enough. Otherwise, to reconstruct randomness for the previous epoch (which may be needed to reconstruct the list of
  * committee members for the previous epoch) we will need to reconstruct committees from ALL past epochs until the genesis
  * epoch.
  */
case class RandomnessTransaction(randomness: Array[Byte],
                                 override val epochID: Long,
                                 override val timestamp: Long) extends TreasuryTransaction(timestamp = timestamp) {

  override type M = SimpleBoxTransaction

  override val transactionTypeId: ModifierTypeId = RandomnessTransaction.TransactionTypeId

  override val serializer = SimpleBoxTransactionCompanion

  override lazy val messageToSign = {
    val superBytes = Bytes.concat(if (newBoxes.nonEmpty) scorex.core.utils.concatBytes(newBoxes.map(_.bytes)) else Array[Byte](),
      scorex.core.utils.concatFixLengthBytes(unlockers.map(_.closedBoxId)),
      Longs.toByteArray(timestamp),
      Longs.toByteArray(fee))

    Bytes.concat(randomness, Longs.toByteArray(epochID), superBytes)
  }

  override lazy val json: Json = Map(
    "id" -> Base58.encode(id).asJson,
    "randomness" -> Base58.encode(randomness).asJson,
    "timestamp" -> timestamp.asJson
  ).asJson

  lazy val semanticValidity: Try[Unit] = Try {
    require(from.size == 0)
    require(signatures.size == 0)
    require(to.size == 0)
    require(fee == 0)
    require(timestamp >= 0)
  }

  override def toString: String = s"RandomnessTransaction(${json.noSpaces})"
}

object RandomnessTransaction {
  val TransactionTypeId: scorex.core.ModifierTypeId = RandomnessTxTypeId

  def apply(randomness: Array[Byte],
            epochID: Long,
            timestamp: Long): RandomnessTransaction = {

    new RandomnessTransaction(randomness, epochID, timestamp)
  }

  def create(trState: TreasuryState): Try[RandomnessTransaction] = Try {
    val timestamp = System.currentTimeMillis()

    RandomnessTransaction(trState.getRandomness, trState.epochNum, timestamp)
  }
}

object RandomnessTransactionCompanion extends Serializer[RandomnessTransaction] {
  def toBytes(t: RandomnessTransaction): Array[Byte] = {
    Bytes.concat(
      Ints.toByteArray(t.randomness.size),
      t.randomness,
      Longs.toByteArray(t.epochID),
      Longs.toByteArray(t.timestamp),
    )
  }

  def parseBytes(bytes: Array[Byte]): Try[RandomnessTransaction] = Try {
    val size = Ints.fromByteArray(bytes.slice(0,4))
    val randomness = bytes.slice(4, 4+size)
    val s = 4+size

    val epochID = Longs.fromByteArray(bytes.slice(s,s+8))
    val timestamp = Longs.fromByteArray(bytes.slice(s+8,s+16))

    RandomnessTransaction(randomness, epochID, timestamp)
  }
}
