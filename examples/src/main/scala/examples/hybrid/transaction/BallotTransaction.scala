package examples.hybrid.transaction

import com.google.common.primitives.{Bytes, Ints, Longs}
import examples.commons.{SimpleBoxTransaction, SimpleBoxTransactionCompanion}
import examples.hybrid.TreasuryManager
import examples.hybrid.transaction.BallotTransaction.VoterType
import examples.hybrid.transaction.BallotTransaction.VoterType.VoterType
import io.circe.Json
import io.circe.syntax._
import scorex.core.ModifierTypeId
import scorex.core.serialization.Serializer
import scorex.core.transaction.box.proposition.PublicKey25519Proposition
import scorex.crypto.encode.Base58
import scorex.crypto.signatures.{Curve25519, PublicKey}
import treasury.crypto.core.PubKey
import treasury.crypto.voting.ballots.{Ballot, BallotCompanion}

import scala.util.Try

case class BallotTransaction(pubKey: PublicKey25519Proposition, // previously registered voter/expert public key. TODO: Probably we can include only id instead of the whole key
                             voterType: VoterType,
                             ballots: Seq[Ballot],
                             override val epochID: Long,
                             override val timestamp: Long) extends TreasuryTransaction(timestamp) {

  override type M = SimpleBoxTransaction

  override val transactionTypeId: ModifierTypeId = BallotTransaction.TransactionTypeId

  override val serializer = SimpleBoxTransactionCompanion

  override lazy val messageToSign = {
    val superBytes = Bytes.concat(if (newBoxes.nonEmpty) scorex.core.utils.concatBytes(newBoxes.map(_.bytes)) else Array[Byte](),
      scorex.core.utils.concatFixLengthBytes(unlockers.map(_.closedBoxId)),
      Longs.toByteArray(timestamp),
      Longs.toByteArray(fee))

    Bytes.concat(
      pubKey.bytes,
      Ints.toByteArray(voterType.id),
      ballots.foldLeft(Array[Byte]())((a,b) => Bytes.concat(a, b.bytes)),
      Longs.toByteArray(epochID),
      superBytes)
  }

  override lazy val json: Json = Map("id" -> Base58.encode(id).asJson).asJson //TODO

  override lazy val semanticValidity: Try[Unit] = Try(Unit) //TODO

  override def toString: String = s"BallotTransaction(${json.noSpaces})"
}

object BallotTransaction {

  object VoterType extends Enumeration {
    type VoterType = Value
    val Expert, Voter = Value
  }

  val TransactionTypeId: scorex.core.ModifierTypeId = BallotTxTypeId

  def apply(pubKey: PublicKey25519Proposition,
            voterType: VoterType,
            ballots: Seq[Ballot],
            epochID: Long,
            timestamp: Long): BallotTransaction = {
    new BallotTransaction(pubKey, voterType, ballots, epochID, timestamp)
  }

  def create(pubKey: PublicKey25519Proposition,
             voterType: VoterType,
             ballots: Seq[Ballot],
             epochID: Long): Try[BallotTransaction] = Try {
    val timestamp = System.currentTimeMillis()
    BallotTransaction(pubKey, voterType, ballots, epochID, timestamp)
  }
}

object BallotTransactionCompanion extends Serializer[BallotTransaction] {
  def toBytes(t: BallotTransaction): Array[Byte] = {
    val ballotBytes = t.ballots.foldLeft(Array[Byte]())((a,b) => Bytes.concat(a, b.bytes))
    Bytes.concat(
      t.pubKey.bytes,
      Array(t.voterType.id.toByte),
      Ints.toByteArray(t.ballots.length),
      ballotBytes,
      Longs.toByteArray(t.epochID),
      Longs.toByteArray(t.timestamp)
    )
  }

  def parseBytes(bytes: Array[Byte]): Try[BallotTransaction] = Try {
    val pubKey = PublicKey25519Proposition(PublicKey @@ bytes.slice(0, Curve25519.KeyLength))
    val voterType = VoterType(bytes(Curve25519.KeyLength))
    var s = Curve25519.KeyLength + 1

    val ballotsSize = Ints.fromByteArray(bytes.slice(s,s+4))
    s = s + 4
    val ballots: Seq[Ballot] = (0 until ballotsSize).map { _ =>
      val b = BallotCompanion.parseBytes(bytes.drop(s), TreasuryManager.cs).get
      s = s + b.bytes.length
      b
    }
    val epochID = Longs.fromByteArray(bytes.slice(s,s+8))
    val timestamp = Longs.fromByteArray(bytes.slice(s+8,s+16))

    BallotTransaction(pubKey, voterType, ballots, epochID, timestamp)
  }
}