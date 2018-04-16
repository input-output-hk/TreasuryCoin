package examples.hybrid.transaction.committee

import com.google.common.primitives.{Bytes, Longs}
import examples.commons.{SimpleBoxTransaction, SimpleBoxTransactionCompanion}
import examples.hybrid.TreasuryManager
import examples.hybrid.transaction.{RandomnessSubmissionTxTypeId, SignedTreasuryTransaction}
import io.circe.Json
import io.circe.syntax._
import scorex.core.ModifierTypeId
import scorex.core.serialization.Serializer
import scorex.core.transaction.box.proposition.PublicKey25519Proposition
import scorex.core.transaction.proof.Signature25519
import scorex.core.transaction.state.{PrivateKey25519, PrivateKey25519Companion}
import scorex.crypto.encode.Base58
import scorex.crypto.signatures.{Curve25519, PublicKey, Signature}
import treasury.crypto.core.{Ciphertext, CiphertextSerizlizer}

import scala.util.Try

case class RandomnessSubmissionTransaction(encryptedRandomness: Ciphertext,
                                           override val epochID: Long,
                                           override val pubKey: PublicKey25519Proposition, // previously registered committee signing public key
                                           override val signature: Signature25519,
                                           override val timestamp: Long) extends SignedTreasuryTransaction(timestamp) {

  override type M = SimpleBoxTransaction

  override val transactionTypeId: ModifierTypeId = RandomnessSubmissionTransaction.TransactionTypeId

  override val serializer = SimpleBoxTransactionCompanion

  override lazy val messageToSign = {
    val superBytes = Bytes.concat(if (newBoxes.nonEmpty) scorex.core.utils.concatBytes(newBoxes.map(_.bytes)) else Array[Byte](),
      scorex.core.utils.concatFixLengthBytes(unlockers.map(_.closedBoxId)),
      Longs.toByteArray(timestamp),
      Longs.toByteArray(fee))

    Bytes.concat(
      CiphertextSerizlizer.toBytes(encryptedRandomness),
      Longs.toByteArray(epochID),
      pubKey.bytes,
      superBytes)
  }

  override lazy val json: Json = Map("id" -> Base58.encode(id).asJson).asJson //TODO

  override lazy val semanticValidity: Try[Unit] = Try {
    require(timestamp >= 0)
    require(signature.isValid(pubKey, messageToSign))
  }

  override def toString: String = s"RandomnessSubmissionTransaction (${json.noSpaces})"
}

object RandomnessSubmissionTransaction {

  val TransactionTypeId: scorex.core.ModifierTypeId = RandomnessSubmissionTxTypeId

  def create(privKey: PrivateKey25519,
             ciphertext: Ciphertext,
             epochID: Long): Try[RandomnessSubmissionTransaction] = Try {
    val timestamp = System.currentTimeMillis()
    val fakeSig = Signature25519(Signature @@ Array[Byte]())
    val unsigned = RandomnessSubmissionTransaction(ciphertext, epochID, privKey.publicImage, fakeSig, timestamp)
    val sig = PrivateKey25519Companion.sign(privKey, unsigned.messageToSign)

    RandomnessSubmissionTransaction(ciphertext, epochID, privKey.publicImage, sig, timestamp)
  }
}

object RandomnessSubmissionTransactionCompanion extends Serializer[RandomnessSubmissionTransaction] {

  def toBytes(t: RandomnessSubmissionTransaction): Array[Byte] = {
    Bytes.concat(
      CiphertextSerizlizer.toBytes(t.encryptedRandomness),
      Longs.toByteArray(t.epochID),
      t.pubKey.bytes,
      t.signature.bytes,
      Longs.toByteArray(t.timestamp)
    )
  }

  def parseBytes(bytes: Array[Byte]): Try[RandomnessSubmissionTransaction] = Try {
    val encryptedRandomness = CiphertextSerizlizer.parseBytes(bytes, TreasuryManager.cs).get
    var s = CiphertextSerizlizer.toBytes(encryptedRandomness).size

    val epochID = Longs.fromByteArray(bytes.slice(s,s+8))
    val pubKey = PublicKey25519Proposition(PublicKey @@ bytes.slice(s+8, s+8+Curve25519.KeyLength))
    s = s + 8 + Curve25519.KeyLength
    val sig = Signature25519(Signature @@ bytes.slice(s, s+Curve25519.SignatureLength))
    s = s + Curve25519.SignatureLength
    val timestamp = Longs.fromByteArray(bytes.slice(s,s+8))

    RandomnessSubmissionTransaction(encryptedRandomness, epochID, pubKey, sig, timestamp)
  }
}
