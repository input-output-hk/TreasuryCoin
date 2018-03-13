package examples.hybrid.transaction

import com.google.common.primitives.{Bytes, Ints, Longs}
import examples.commons.{SimpleBoxTransaction, SimpleBoxTransactionCompanion, Value}
import examples.hybrid.wallet.HWallet
import io.circe.Json
import io.circe.syntax._
import scorex.core.ModifierTypeId
import scorex.core.serialization.Serializer
import scorex.core.transaction.box.proposition.PublicKey25519Proposition
import scorex.crypto.signatures.{Curve25519, PublicKey}

import scala.util.Try


case class ProposalTransaction(name: String,
                               requestedSum: Value,
                               recipient: PublicKey25519Proposition,
                               epochID: Long,
                               override val timestamp: Long) extends TreasuryTransaction(timestamp = timestamp) {

  override type M = SimpleBoxTransaction

  override val transactionTypeId: ModifierTypeId = ProposalTransaction.TransactionTypeId

  override val serializer = SimpleBoxTransactionCompanion

  override lazy val messageToSign = {
    val superBytes = Bytes.concat(if (newBoxes.nonEmpty) scorex.core.utils.concatBytes(newBoxes.map(_.bytes)) else Array[Byte](),
      scorex.core.utils.concatFixLengthBytes(unlockers.map(_.closedBoxId)),
      Longs.toByteArray(timestamp),
      Longs.toByteArray(fee))

    Bytes.concat(
      name.getBytes,
      Longs.toByteArray(requestedSum),
      recipient.bytes,
      Longs.toByteArray(epochID),
      superBytes)
  }

  override lazy val json: Json = Map("name" -> name.asJson).asJson //TODO

  override lazy val semanticValidity: Try[Unit] = Try(Unit) //TODO

  override def toString: String = s"ProposalTransaction(${json.noSpaces})"
}

object ProposalTransaction {
  val TransactionTypeId: scorex.core.ModifierTypeId = ProposalTxTypeId

  def apply(name: String,
            requestedSum: Value,
            recipient: PublicKey25519Proposition,
            epochID: Long,
            timestamp: Long): ProposalTransaction = {

    new ProposalTransaction(name, requestedSum, recipient, epochID, timestamp)
  }

  def create(w: HWallet,
             name: String,
             requestedSum: Value,
             recipient: PublicKey25519Proposition,
             epochID: Long): Try[ProposalTransaction] = Try {

    val timestamp = System.currentTimeMillis()
    ProposalTransaction(name, requestedSum, recipient, epochID, timestamp)
  }
}

object ProposalTransactionCompanion extends Serializer[ProposalTransaction] {
  def toBytes(t: ProposalTransaction): Array[Byte] = {
    val nameBytes = t.name.getBytes("UTF-8")
    Bytes.concat(
      Ints.toByteArray(nameBytes.length),
      nameBytes,
      Longs.toByteArray(t.requestedSum),
      t.recipient.bytes,
      Longs.toByteArray(t.epochID),
      Longs.toByteArray(t.timestamp)
    )
  }

  def parseBytes(bytes: Array[Byte]): Try[ProposalTransaction] = Try {
    val nameBytesLen = Ints.fromByteArray(bytes.slice(0,4))
    val name = new String(bytes.slice(4,4+nameBytesLen), "UTF-8")
    var s = 4 + nameBytesLen
    val requestedSum = Value @@ Longs.fromByteArray(bytes.slice(s,s+8))
    val recipient = PublicKey25519Proposition(PublicKey @@ bytes.slice(s+8, s+8+Curve25519.KeyLength))
    s += 8 + Curve25519.KeyLength
    val epochID = Longs.fromByteArray(bytes.slice(s,s+8))
    val timestamp = Longs.fromByteArray(bytes.slice(s+8,s+16))

    ProposalTransaction(name, requestedSum, recipient, epochID, timestamp)
  }
}
