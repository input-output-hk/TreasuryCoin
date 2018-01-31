package examples.hybrid.transaction

import com.google.common.primitives.{Bytes, Ints, Longs}
import examples.commons.{SimpleBoxTransaction, SimpleBoxTransactionCompanion}
import examples.hybrid.TreasuryManager
import examples.hybrid.TreasuryManager.Role
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
import treasury.crypto.core.PubKey

import scala.util.Try

case class CommitteeRegisterTransaction(proxyPubKey: PubKey,
                                        override val epochID: Long,
                                        override val pubKey: PublicKey25519Proposition,
                                        override val signature: Signature25519,
                                        override val timestamp: Long) extends SignedTreasuryTransaction(timestamp) {

  override type M = SimpleBoxTransaction

  override val transactionTypeId: ModifierTypeId = CommitteeRegisterTransaction.TransactionTypeId

  override val serializer = SimpleBoxTransactionCompanion

  override lazy val messageToSign = {
    val superBytes = Bytes.concat(if (newBoxes.nonEmpty) scorex.core.utils.concatBytes(newBoxes.map(_.bytes)) else Array[Byte](),
      scorex.core.utils.concatFixLengthBytes(unlockers.map(_.closedBoxId)),
      Longs.toByteArray(timestamp),
      Longs.toByteArray(fee))

    Bytes.concat(pubKey.bytes,
      proxyPubKey.getEncoded(true),
      Longs.toByteArray(epochID),
      superBytes)
  }

  override lazy val json: Json = Map("id" -> Base58.encode(id).asJson).asJson //TODO

  override lazy val semanticValidity: Try[Unit] = Try {
    require(timestamp >= 0)
    require(signature.isValid(pubKey, messageToSign))
  }

  override def toString: String = s"CommitteeRegisterTransaction(${json.noSpaces})"
}

object CommitteeRegisterTransaction {
  val TransactionTypeId: scorex.core.ModifierTypeId = CommitteeRegisterTxTypeId

  def create(w: HWallet, epochID: Long): Try[CommitteeRegisterTransaction] = Try {
    val proxyPubKey = w.generateNewTreasuryCommitteeSecret(epochID)
    val signingPubKey = w.generateNewTreasurySigningSecret(Role.Committee, epochID)
    val signingPrivKey = w.treasurySigningSecretByPubKey(epochID, signingPubKey).get.privKey
    val timestamp = System.currentTimeMillis()

    val fakeSig = Signature25519(Signature @@ Array[Byte]())
    val unsigned = CommitteeRegisterTransaction(proxyPubKey, epochID, signingPubKey, fakeSig, timestamp)
    val sig = PrivateKey25519Companion.sign(signingPrivKey, unsigned.messageToSign)

    CommitteeRegisterTransaction(proxyPubKey, epochID, signingPubKey, sig, timestamp)
  }
}

object CommitteeRegisterTransactionCompanion extends Serializer[CommitteeRegisterTransaction] {

  def toBytes(t: CommitteeRegisterTransaction): Array[Byte] = {
    val keyBytes = t.proxyPubKey.getEncoded(true)
    Bytes.concat(
      Ints.toByteArray(keyBytes.length),
      keyBytes,
      Longs.toByteArray(t.epochID),
      t.pubKey.bytes,
      t.signature.bytes,
      Longs.toByteArray(t.timestamp)
    )
  }

  def parseBytes(bytes: Array[Byte]): Try[CommitteeRegisterTransaction] = Try {
    val keySize = Ints.fromByteArray(bytes.slice(0,4))
    val pubKey = TreasuryManager.cs.decodePoint(bytes.slice(4,keySize+4))
    var s = 4+keySize
    val epochID = Longs.fromByteArray(bytes.slice(s,s+8))
    val signingPubKey = PublicKey25519Proposition(PublicKey @@ bytes.slice(s+8, s+8+Curve25519.KeyLength))
    s = s+8+Curve25519.KeyLength
    val sig = Signature25519(Signature @@ bytes.slice(s, s+Curve25519.SignatureLength))
    s = s+Curve25519.SignatureLength
    val timestamp = Longs.fromByteArray(bytes.slice(s,s+8))

    CommitteeRegisterTransaction(pubKey, epochID, signingPubKey, sig, timestamp)
  }
}

