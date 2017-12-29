package examples.hybrid.transaction

import com.google.common.primitives.{Bytes, Ints, Longs}
import examples.hybrid.TreasuryManager
import examples.hybrid.transaction.RegisterTransaction.Role
import examples.hybrid.transaction.RegisterTransaction.Role.Role
import examples.hybrid.wallet.HWallet
import io.circe.Json
import io.circe.syntax._
import scorex.core.ModifierTypeId
import scorex.core.serialization.Serializer
import scorex.crypto.encode.Base58
import treasury.crypto.core.{Cryptosystem, KeyPair, PubKey}

import scala.util.Try

case class RegisterTransaction(role: Role,
                               pubKey: PubKey,
                               epochID: Long,
                               override val timestamp: Long) extends TreasuryTransaction(timestamp) {

  override type M = RegisterTransaction

  override val modifierTypeId: ModifierTypeId = RegisterTransaction.ModifierTypeId

  override val serializer = RegisterTransactionCompanion

  override lazy val messageToSign = {
    val superBytes = Bytes.concat(if (newBoxes.nonEmpty) scorex.core.utils.concatBytes(newBoxes.map(_.bytes)) else Array[Byte](),
      scorex.core.utils.concatFixLengthBytes(unlockers.map(_.closedBoxId)),
      Longs.toByteArray(timestamp),
      Longs.toByteArray(fee))

    Bytes.concat(Ints.toByteArray(role.id),
      pubKey.getEncoded(true),
      Longs.toByteArray(epochID),
      superBytes)
  }

  override lazy val json: Json = Map("id" -> Base58.encode(id).asJson).asJson //TODO

  override lazy val semanticValidity: Try[Unit] = Try(Unit) //TODO

  override def toString: String = s"RegisterTransaction(${json.noSpaces})"
}

object RegisterTransaction {
  val ModifierTypeId: scorex.core.ModifierTypeId = RegisterTxTypeId

  object Role extends Enumeration {
    type Role = Value
    val Committee, Expert, Voter = Value
  }

  def apply(role: Role,
            committeePubKey: PubKey,
            epochID: Long,
            timestamp: Long): RegisterTransaction = {

    new RegisterTransaction(role, committeePubKey, epochID, timestamp)
  }

  // TODO: store new keypair in HWallet?
  def create(w: HWallet,
             role: Role,
             epochID: Long): Try[(RegisterTransaction, KeyPair)] = Try {
    val keyPair = TreasuryManager.cs.createKeyPair
    //val acc = w.secretByPublicImage(w.boxes().head.box.proposition).get
    val timestamp = System.currentTimeMillis()
    (RegisterTransaction(role, keyPair._2, epochID, timestamp), keyPair)
  }
}

object RegisterTransactionCompanion extends Serializer[RegisterTransaction] {
  def toBytes(t: RegisterTransaction): Array[Byte] = {
    val keyBytes = t.pubKey.getEncoded(true)
    Bytes.concat(
      Array(t.role.id.toByte),
      Ints.toByteArray(keyBytes.length),
      keyBytes,
      Longs.toByteArray(t.epochID),
      Longs.toByteArray(t.timestamp)
    )
  }

  def parseBytes(bytes: Array[Byte]): Try[RegisterTransaction] = Try {
    val role: Role = Role(bytes(0))
    val keySize = Ints.fromByteArray(bytes.slice(1,5))
    val committeePubKey = TreasuryManager.cs.decodePoint(bytes.slice(5,keySize+5))
    val s = 5+keySize
    val epochID = Longs.fromByteArray(bytes.slice(s,s+8))
    val timestamp = Longs.fromByteArray(bytes.slice(s+8,s+16))

    RegisterTransaction(role, committeePubKey, epochID, timestamp)
  }
}
