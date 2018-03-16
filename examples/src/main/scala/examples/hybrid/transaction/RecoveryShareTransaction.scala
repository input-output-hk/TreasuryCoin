package examples.hybrid.transaction

import com.google.common.primitives.{Bytes, Ints, Longs}
import examples.commons.{SimpleBoxTransaction, SimpleBoxTransactionCompanion}
import examples.hybrid.TreasuryManager
import examples.hybrid.transaction.RecoveryShareTransaction.OpenedShareWithId
import io.circe.Json
import io.circe.syntax._
import scorex.core.ModifierTypeId
import scorex.core.serialization.Serializer
import scorex.core.transaction.box.proposition.PublicKey25519Proposition
import scorex.core.transaction.proof.Signature25519
import scorex.core.transaction.state.{PrivateKey25519, PrivateKey25519Companion}
import scorex.crypto.encode.Base58
import scorex.crypto.signatures.{Curve25519, PublicKey, Signature}
import treasury.crypto.keygen.datastructures.round4.{OpenedShare, OpenedShareSerializer}

import scala.util.Try

/**
  * This is a special type of transactions that is used by a committee member to submit his share for key recovery
  * process
  *
  * @param openedShares (id, openedShare) id of violator and corresponding opened share of his private key
  */
case class RecoveryShareTransaction(openedShares: Seq[OpenedShareWithId],
                                    override val epochID: Long,
                                    override val pubKey: PublicKey25519Proposition, // previously registered committee public key
                                    override val signature: Signature25519,
                                    override val timestamp: Long) extends SignedTreasuryTransaction(timestamp) {

  override type M = SimpleBoxTransaction

  override val transactionTypeId: ModifierTypeId = RecoveryShareTransaction.TransactionTypeId

  override val serializer = SimpleBoxTransactionCompanion

  override lazy val messageToSign = {
    val superBytes = Bytes.concat(if (newBoxes.nonEmpty) scorex.core.utils.concatBytes(newBoxes.map(_.bytes)) else Array[Byte](),
      scorex.core.utils.concatFixLengthBytes(unlockers.map(_.closedBoxId)),
      Longs.toByteArray(timestamp),
      Longs.toByteArray(fee))

    val openedSharesBytes = openedShares.foldLeft(Array[Byte]()) { (a,b) =>
      Bytes.concat(a, Bytes.concat(Ints.toByteArray(b.violatorId), b.openedShare.bytes))
    }

    Bytes.concat(openedSharesBytes, Longs.toByteArray(epochID), superBytes)
  }

  override lazy val json: Json = Map("id" -> Base58.encode(id).asJson).asJson //TODO

  override lazy val semanticValidity: Try[Unit] = Try {
    require(timestamp >= 0)
    require(signature.isValid(pubKey, messageToSign))
  }

  override def toString: String = s"RecoveryShareTransaction (${json.noSpaces})"
}

object RecoveryShareTransaction {

  case class OpenedShareWithId(violatorId: Int, openedShare: OpenedShare)

  val TransactionTypeId: scorex.core.ModifierTypeId = RecoveryShareTxTypeId

  def create(privKey: PrivateKey25519,
             openedShares: Seq[OpenedShareWithId],
             epochID: Long): Try[RecoveryShareTransaction] = Try {
    val timestamp = System.currentTimeMillis()
    val fakeSig = Signature25519(Signature @@ Array[Byte]())
    val unsigned = RecoveryShareTransaction(openedShares, epochID, privKey.publicImage, fakeSig, timestamp)
    val sig = PrivateKey25519Companion.sign(privKey, unsigned.messageToSign)

    RecoveryShareTransaction(openedShares, epochID, privKey.publicImage, sig, timestamp)
  }
}

object RecoveryShareTransactionCompanion extends Serializer[RecoveryShareTransaction] {

  def toBytes(t: RecoveryShareTransaction): Array[Byte] = {
    val openedSharesBytes = t.openedShares.foldLeft(Array[Byte]()) { (a,b) =>
      Bytes.concat(a, Bytes.concat(Ints.toByteArray(b.violatorId), b.openedShare.bytes))
    }

    Bytes.concat(
      Ints.toByteArray(t.openedShares.size),
      openedSharesBytes,
      Longs.toByteArray(t.epochID),
      t.pubKey.bytes,
      t.signature.bytes,
      Longs.toByteArray(t.timestamp)
    )
  }

  def parseBytes(bytes: Array[Byte]): Try[RecoveryShareTransaction] = Try {

    val sharesSize = Ints.fromByteArray(bytes.slice(0,4))
    var s = 4
    val openedShares: Seq[OpenedShareWithId] = (0 until sharesSize).map { _ =>
      val violatorId = Ints.fromByteArray(bytes.slice(s, s+4))
      val openedShare = OpenedShareSerializer.parseBytes(bytes.drop(s+4), TreasuryManager.cs).get
      s = s + 4 + openedShare.bytes.length
      OpenedShareWithId(violatorId, openedShare)
    }
    val epochID = Longs.fromByteArray(bytes.slice(s,s+8))
    val pubKey = PublicKey25519Proposition(PublicKey @@ bytes.slice(s+8, s+8+Curve25519.KeyLength))
    s = s + 8 + Curve25519.KeyLength
    val sig = Signature25519(Signature @@ bytes.slice(s, s+Curve25519.SignatureLength))
    s = s + Curve25519.SignatureLength
    val timestamp = Longs.fromByteArray(bytes.slice(s,s+8))

    RecoveryShareTransaction(openedShares, epochID, pubKey, sig, timestamp)
  }
}