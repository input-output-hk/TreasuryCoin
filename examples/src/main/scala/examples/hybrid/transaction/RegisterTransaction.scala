package examples.hybrid.transaction

import com.google.common.primitives.{Bytes, Ints, Longs}
import examples.commons.{SimpleBoxTransaction, SimpleBoxTransactionCompanion}
import examples.hybrid.TreasuryManager.Role
import examples.hybrid.TreasuryManager.Role.Role
import examples.hybrid.wallet.HWallet
import io.circe.Json
import io.circe.syntax._
import scorex.core.ModifierTypeId
import scorex.core.serialization.Serializer
import scorex.core.transaction.box.proposition.PublicKey25519Proposition
import scorex.core.transaction.proof.Signature25519
import scorex.core.transaction.state.PrivateKey25519Companion
import scorex.crypto.encode.Base58
import scorex.crypto.signatures.{Curve25519, PublicKey, Signature}

import scala.util.Try

case class RegisterTransaction(role: Role,
                               override val epochID: Long,
                               override val pubKey: PublicKey25519Proposition,
                               override val signature: Signature25519,
                               override val timestamp: Long) extends SignedTreasuryTransaction(timestamp) {
  require(role == Role.Voter || role == Role.Expert)

  override type M = SimpleBoxTransaction

  override val transactionTypeId: ModifierTypeId = RegisterTransaction.TransactionTypeId

  override val serializer = SimpleBoxTransactionCompanion

  override lazy val messageToSign = {
    val superBytes = Bytes.concat(if (newBoxes.nonEmpty) scorex.core.utils.concatBytes(newBoxes.map(_.bytes)) else Array[Byte](),
      scorex.core.utils.concatFixLengthBytes(unlockers.map(_.closedBoxId)),
      Longs.toByteArray(timestamp),
      Longs.toByteArray(fee))

    Bytes.concat(Ints.toByteArray(role.id),
      pubKey.bytes,
      Longs.toByteArray(epochID),
      superBytes)
  }

  override lazy val json: Json = Map("id" -> Base58.encode(id).asJson).asJson //TODO

  override lazy val semanticValidity: Try[Unit] = Try {
    require(timestamp >= 0)
    require(signature.isValid(pubKey, messageToSign))
  }

  override def toString: String = s"RegisterTransaction(${json.noSpaces})"
}

object RegisterTransaction {
  val TransactionTypeId: scorex.core.ModifierTypeId = RegisterTxTypeId

  def create(w: HWallet,
             role: Role,
             epochID: Long): Try[RegisterTransaction] = Try {
    val pubKey = w.generateNewTreasurySigningSecret(role, epochID)
    val privKey = w.treasurySigningSecretByPubKey(epochID, pubKey).get.privKey
    val timestamp = System.currentTimeMillis()

    val fakeSig = Signature25519(Signature @@ Array[Byte]())
    val unsigned = RegisterTransaction(role, epochID, pubKey, fakeSig, timestamp)
    val sig = PrivateKey25519Companion.sign(privKey, unsigned.messageToSign)

    RegisterTransaction(role, epochID, pubKey, sig, timestamp)
  }
}

object RegisterTransactionCompanion extends Serializer[RegisterTransaction] {

  def toBytes(t: RegisterTransaction): Array[Byte] = {
    Bytes.concat(
      Array(t.role.id.toByte),
      Longs.toByteArray(t.epochID),
      t.pubKey.bytes,
      t.signature.bytes,
      Longs.toByteArray(t.timestamp)
    )
  }

  def parseBytes(bytes: Array[Byte]): Try[RegisterTransaction] = Try {
    val role: Role = Role(bytes(0))
    val epochID = Longs.fromByteArray(bytes.slice(1,9))
    val pubKey = PublicKey25519Proposition(PublicKey @@ bytes.slice(9, Curve25519.KeyLength+9))
    var s = 9+Curve25519.KeyLength
    val sig = Signature25519(Signature @@ bytes.slice(s, s+Curve25519.SignatureLength))
    s = s + Curve25519.SignatureLength
    val timestamp = Longs.fromByteArray(bytes.slice(s,s+8))

    RegisterTransaction(role, epochID, pubKey, sig, timestamp)
  }
}
