package examples.hybrid.transaction.committee

import com.google.common.primitives.{Bytes, Ints, Longs}
import examples.commons.{SimpleBoxTransaction, SimpleBoxTransactionCompanion}
import examples.hybrid.TreasuryManager
import examples.hybrid.transaction.committee.DecryptionShareTransaction.DecryptionRound
import examples.hybrid.transaction.committee.DecryptionShareTransaction.DecryptionRound.DecryptionRound
import examples.hybrid.transaction.{DecryptionShareTxTypeId, SignedTreasuryTransaction}
import io.circe.Json
import io.circe.syntax._
import scorex.core.ModifierTypeId
import scorex.core.serialization.Serializer
import scorex.core.transaction.box.proposition.PublicKey25519Proposition
import scorex.core.transaction.proof.Signature25519
import scorex.core.transaction.state.{PrivateKey25519, PrivateKey25519Companion}
import scorex.crypto.encode.Base58
import scorex.crypto.signatures.{Curve25519, PublicKey, Signature}
import treasury.crypto.keygen.datastructures.{C1Share, C1ShareSerializer}

import scala.util.Try

case class DecryptionShareTransaction(round: DecryptionRound,
                                      c1Shares: Seq[C1Share],
                                      override val epochID: Long,
                                      override val pubKey: PublicKey25519Proposition, // previously registered committee public key
                                      override val signature: Signature25519,
                                      override val timestamp: Long) extends SignedTreasuryTransaction(timestamp) {

  override type M = SimpleBoxTransaction

  override val transactionTypeId: ModifierTypeId = DecryptionShareTransaction.TransactionTypeId

  override val serializer = SimpleBoxTransactionCompanion

  override lazy val messageToSign = {
    val superBytes = Bytes.concat(if (newBoxes.nonEmpty) scorex.core.utils.concatBytes(newBoxes.map(_.bytes)) else Array[Byte](),
      scorex.core.utils.concatFixLengthBytes(unlockers.map(_.closedBoxId)),
      Longs.toByteArray(timestamp),
      Longs.toByteArray(fee))

    Bytes.concat(
      pubKey.bytes,
      Ints.toByteArray(round.id),
      c1Shares.foldLeft(Array[Byte]())((a,b) => Bytes.concat(a, b.bytes)),
      Longs.toByteArray(epochID),
      superBytes)
  }

  override lazy val json: Json = Map("id" -> Base58.encode(id).asJson).asJson //TODO

  override lazy val semanticValidity: Try[Unit] = Try {
    require(timestamp >= 0)
    require(signature.isValid(pubKey, messageToSign))
  }

  override def toString: String = s"DecryptionShareTransaction (${json.noSpaces})"
}

object DecryptionShareTransaction {

  val TransactionTypeId: scorex.core.ModifierTypeId = DecryptionShareTxTypeId

  object DecryptionRound extends Enumeration {
    type DecryptionRound = Value
    val R1, R2: DecryptionRound = Value
  }

  def create(privKey: PrivateKey25519,
             round: DecryptionRound,
             c1Shares: Seq[C1Share],
             epochID: Long): Try[DecryptionShareTransaction] = Try {
    val timestamp = System.currentTimeMillis()
    val fakeSig = Signature25519(Signature @@ Array[Byte]())
    val unsigned = DecryptionShareTransaction(round, c1Shares, epochID, privKey.publicImage, fakeSig, timestamp)
    val sig = PrivateKey25519Companion.sign(privKey, unsigned.messageToSign)

    DecryptionShareTransaction(round, c1Shares, epochID, privKey.publicImage, sig, timestamp)
  }
}

object DecryptionShareTransactionCompanion extends Serializer[DecryptionShareTransaction] {
  
  def toBytes(t: DecryptionShareTransaction): Array[Byte] = {
    val c1SharesBytes = t.c1Shares.foldLeft(Array[Byte]())((a,b) => Bytes.concat(a, b.bytes))
    Bytes.concat(
      Array(t.round.id.toByte),
      Ints.toByteArray(t.c1Shares.length),
      c1SharesBytes,
      Longs.toByteArray(t.epochID),
      t.pubKey.bytes,
      t.signature.bytes,
      Longs.toByteArray(t.timestamp)
    )
  }

  def parseBytes(bytes: Array[Byte]): Try[DecryptionShareTransaction] = Try {
    val round = DecryptionRound(bytes(0))
    val c1SharesSize = Ints.fromByteArray(bytes.slice(1,5))
    var s = 5
    val c1Shares: Seq[C1Share] = (0 until c1SharesSize).map { _ =>
      val b = C1ShareSerializer.parseBytes(bytes.drop(s), TreasuryManager.cs).get
      s = s + b.bytes.length
      b
    }
    val epochID = Longs.fromByteArray(bytes.slice(s,s+8))
    val pubKey = PublicKey25519Proposition(PublicKey @@ bytes.slice(s+8, s+8+Curve25519.KeyLength))
    s = s + 8 + Curve25519.KeyLength
    val sig = Signature25519(Signature @@ bytes.slice(s, s+Curve25519.SignatureLength))
    s = s + Curve25519.SignatureLength
    val timestamp = Longs.fromByteArray(bytes.slice(s,s+8))

    DecryptionShareTransaction(round, c1Shares, epochID, pubKey, sig, timestamp)

  }
}
