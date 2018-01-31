package examples.hybrid.transaction

import com.google.common.primitives.{Bytes, Ints, Longs}
import examples.commons.{SimpleBoxTransaction, SimpleBoxTransactionCompanion}
import examples.hybrid.TreasuryManager
import examples.hybrid.transaction.RegisterTransaction.Role
import examples.hybrid.transaction.RegisterTransaction.Role.Role
import examples.hybrid.wallet.HWallet
import io.circe.Json
import io.circe.syntax._
import scorex.core.ModifierTypeId
import scorex.core.serialization.Serializer
import scorex.core.transaction.box.proposition.PublicKey25519Proposition
import scorex.crypto.encode.Base58
import scorex.crypto.signatures.{Curve25519, PublicKey}
import treasury.crypto.core.{Cryptosystem, KeyPair, PubKey}

import scala.util.Try

case class CommitteeRegisterTransaction(signingPubKey: PublicKey25519Proposition,
                                        proxyPubKey: PubKey,
                                        epochID: Long,
                                        override val timestamp: Long) extends TreasuryTransaction(timestamp) {

  override type M = SimpleBoxTransaction

  override val transactionTypeId: ModifierTypeId = CommitteeRegisterTransaction.TransactionTypeId

  override val serializer = SimpleBoxTransactionCompanion

  override lazy val messageToSign = {
    val superBytes = Bytes.concat(if (newBoxes.nonEmpty) scorex.core.utils.concatBytes(newBoxes.map(_.bytes)) else Array[Byte](),
      scorex.core.utils.concatFixLengthBytes(unlockers.map(_.closedBoxId)),
      Longs.toByteArray(timestamp),
      Longs.toByteArray(fee))

    Bytes.concat(signingPubKey.bytes,
      proxyPubKey.getEncoded(true),
      Longs.toByteArray(epochID),
      superBytes)
  }

  override lazy val json: Json = Map("id" -> Base58.encode(id).asJson).asJson //TODO

  override lazy val semanticValidity: Try[Unit] = Try(Unit) //TODO

  override def toString: String = s"CommitteeRegisterTransaction(${json.noSpaces})"
}

object CommitteeRegisterTransaction {
  val TransactionTypeId: scorex.core.ModifierTypeId = CommitteeRegisterTxTypeId

  def apply(signingPubKey: PublicKey25519Proposition,
            committeePubKey: PubKey,
            epochID: Long,
            timestamp: Long): CommitteeRegisterTransaction = {
    new CommitteeRegisterTransaction(signingPubKey, committeePubKey, epochID, timestamp)
  }

  def create(w: HWallet, epochID: Long): Try[CommitteeRegisterTransaction] = Try {
    val committeePubKey = w.generateNewTreasuryCommitteeSecret(epochID)
    val signingPubKey = w.generateNewTreasurySigningSecret(Role.Committee, epochID)
    val timestamp = System.currentTimeMillis()
    CommitteeRegisterTransaction(signingPubKey, committeePubKey, epochID, timestamp)
  }
}

object CommitteeRegisterTransactionCompanion extends Serializer[CommitteeRegisterTransaction] {

  def toBytes(t: CommitteeRegisterTransaction): Array[Byte] = {
    val keyBytes = t.proxyPubKey.getEncoded(true)
    Bytes.concat(
      t.signingPubKey.bytes,
      Ints.toByteArray(keyBytes.length),
      keyBytes,
      Longs.toByteArray(t.epochID),
      Longs.toByteArray(t.timestamp)
    )
  }

  def parseBytes(bytes: Array[Byte]): Try[CommitteeRegisterTransaction] = Try {
    val signingPubKey = PublicKey25519Proposition(PublicKey @@ bytes.slice(0, Curve25519.KeyLength))
    var s = Curve25519.KeyLength
    val keySize = Ints.fromByteArray(bytes.slice(s,s+4))
    val pubKey = TreasuryManager.cs.decodePoint(bytes.slice(s+4,s+keySize+4))
    s = s+4+keySize
    val epochID = Longs.fromByteArray(bytes.slice(s,s+8))
    val timestamp = Longs.fromByteArray(bytes.slice(s+8,s+16))

    CommitteeRegisterTransaction(signingPubKey, pubKey, epochID, timestamp)
  }
}

