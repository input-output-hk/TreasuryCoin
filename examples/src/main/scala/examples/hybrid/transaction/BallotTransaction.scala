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
import scorex.core.transaction.proof.Signature25519
import scorex.core.transaction.state.{PrivateKey25519, PrivateKey25519Companion}
import scorex.crypto.encode.Base58
import scorex.crypto.signatures.{Curve25519, PublicKey, Signature}
import treasury.crypto.core.PubKey
import treasury.crypto.voting.ballots.{Ballot, BallotCompanion}

import scala.util.Try

case class BallotTransaction(voterType: VoterType,
                             ballots: Seq[Ballot],
                             override val epochID: Long,
                             override val pubKey: PublicKey25519Proposition, // previously registered voter/expert public key
                             override val signature: Signature25519,
                             override val timestamp: Long) extends SignedTreasuryTransaction(timestamp) {

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

  override lazy val semanticValidity: Try[Unit] = Try {
    require(timestamp >= 0)
    require(signature.isValid(pubKey, messageToSign))
  }

  override def toString: String = s"BallotTransaction(${json.noSpaces})"
}

object BallotTransaction {

  object VoterType extends Enumeration {
    type VoterType = Value
    val Expert, Voter: VoterType = Value
  }

  val TransactionTypeId: scorex.core.ModifierTypeId = BallotTxTypeId

  def create(privKey: PrivateKey25519,
             voterType: VoterType,
             ballots: Seq[Ballot],
             epochID: Long): Try[BallotTransaction] = Try {
    val timestamp = System.currentTimeMillis()
    val fakeSig = Signature25519(Signature @@ Array[Byte]())
    val unsigned = BallotTransaction(voterType, ballots, epochID, privKey.publicImage, fakeSig, timestamp)
    val sig = PrivateKey25519Companion.sign(privKey, unsigned.messageToSign)

    BallotTransaction(voterType, ballots, epochID, privKey.publicImage, sig, timestamp)
  }
}

object BallotTransactionCompanion extends Serializer[BallotTransaction] {
  def toBytes(t: BallotTransaction): Array[Byte] = {
    val ballotBytes = t.ballots.foldLeft(Array[Byte]())((a,b) => Bytes.concat(a, b.bytes))
    Bytes.concat(
      Array(t.voterType.id.toByte),
      Ints.toByteArray(t.ballots.length),
      ballotBytes,
      Longs.toByteArray(t.epochID),
      t.pubKey.bytes,
      t.signature.bytes,
      Longs.toByteArray(t.timestamp)
    )
  }

  def parseBytes(bytes: Array[Byte]): Try[BallotTransaction] = Try {

    val voterType = VoterType(bytes(0))
    val ballotsSize = Ints.fromByteArray(bytes.slice(1,5))
    var s = 5
    val ballots: Seq[Ballot] = (0 until ballotsSize).map { _ =>
      val b = BallotCompanion.parseBytes(bytes.drop(s), TreasuryManager.cs).get
      s = s + b.bytes.length
      b
    }
    val epochID = Longs.fromByteArray(bytes.slice(s,s+8))
    val pubKey = PublicKey25519Proposition(PublicKey @@ bytes.slice(s+8, s+8+Curve25519.KeyLength))
    s = s + 8 + Curve25519.KeyLength
    val sig = Signature25519(Signature @@ bytes.slice(s, s+Curve25519.SignatureLength))
    s = s + Curve25519.SignatureLength
    val timestamp = Longs.fromByteArray(bytes.slice(s,s+8))

    BallotTransaction(voterType, ballots, epochID, pubKey, sig, timestamp)
  }
}