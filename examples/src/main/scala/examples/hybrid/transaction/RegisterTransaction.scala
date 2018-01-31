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
import scorex.crypto.encode.Base58
import scorex.crypto.signatures.{Curve25519, PublicKey}

import scala.util.Try

case class RegisterTransaction(role: Role,
                               pubKey: PublicKey25519Proposition,
                               epochID: Long,
                               override val timestamp: Long) extends TreasuryTransaction(timestamp) {
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

  override lazy val semanticValidity: Try[Unit] = Try(Unit) //TODO

  override def toString: String = s"RegisterTransaction(${json.noSpaces})"
}

object RegisterTransaction {
  val TransactionTypeId: scorex.core.ModifierTypeId = RegisterTxTypeId

  def apply(role: Role,
            pubKey: PublicKey25519Proposition,
            epochID: Long,
            timestamp: Long): RegisterTransaction = {
    new RegisterTransaction(role, pubKey, epochID, timestamp)
  }

  def create(w: HWallet,
             role: Role,
             epochID: Long): Try[RegisterTransaction] = Try {
    val pubKey = w.generateNewTreasurySigningSecret(role, epochID)
    val timestamp = System.currentTimeMillis()
    RegisterTransaction(role, pubKey, epochID, timestamp)
  }
}

object RegisterTransactionCompanion extends Serializer[RegisterTransaction] {

  def toBytes(t: RegisterTransaction): Array[Byte] = {
    Bytes.concat(
      Array(t.role.id.toByte),
      t.pubKey.bytes,
      Longs.toByteArray(t.epochID),
      Longs.toByteArray(t.timestamp)
    )
  }

  def parseBytes(bytes: Array[Byte]): Try[RegisterTransaction] = Try {
    val role: Role = Role(bytes(0))
    val pubKey = PublicKey25519Proposition(PublicKey @@ bytes.slice(1, Curve25519.KeyLength+1))
    val s = 1+Curve25519.KeyLength
    val epochID = Longs.fromByteArray(bytes.slice(s,s+8))
    val timestamp = Longs.fromByteArray(bytes.slice(s+8,s+16))

    RegisterTransaction(role, pubKey, epochID, timestamp)
  }
}
