package examples.hybrid.transaction

import com.google.common.primitives.{Bytes, Ints, Longs}
import examples.commons.{Nonce, SimpleBoxTransaction, SimpleBoxTransactionCompanion, Value}
import examples.hybrid.TreasuryManager
import examples.hybrid.TreasuryManager.Role
import examples.hybrid.TreasuryManager.Role.Role
import examples.hybrid.wallet.HWallet
import io.circe.Json
import io.circe.syntax._
import scorex.core.ModifierTypeId
import scorex.core.serialization.Serializer
import scorex.core.transaction.box.proposition.PublicKey25519Proposition
import scorex.core.transaction.proof.Signature25519
import scorex.core.transaction.state.{PrivateKey25519, PrivateKey25519Companion}
import scorex.crypto.encode.Base58
import scorex.crypto.signatures.{Curve25519, PublicKey, Signature}

import scala.util.Try

case class RegisterTransaction(role: Role,
                               override val epochID: Long,
                               override val from: IndexedSeq[(PublicKey25519Proposition, Nonce)],
                               override val to: IndexedSeq[(PublicKey25519Proposition, Value)],
                               override val signatures: IndexedSeq[Signature25519],
                               override val fee: Long,
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

  def apply(role: Role,
            epochId: Long,
            from: IndexedSeq[(PrivateKey25519, Nonce)],
            to: IndexedSeq[(PublicKey25519Proposition, Value)],
            fee: Long,
            signingKey: PrivateKey25519,
            timestamp: Long): RegisterTransaction = {
    val fromPub = from.map { case (pr, n) => pr.publicImage -> n }
    val fakeSig = Signature25519(Signature @@ Array[Byte]())
    val fakeSigs = from.map(_ => fakeSig)

    val unsigned = RegisterTransaction(role, epochId, fromPub, to, fakeSigs, fee, signingKey.publicImage, fakeSig, timestamp)

    val msg = unsigned.messageToSign
    val sigs = from.map { case (priv, _) => PrivateKey25519Companion.sign(priv, msg) }
    val sig = PrivateKey25519Companion.sign(signingKey, unsigned.messageToSign)

    RegisterTransaction(role, epochId, fromPub, to, sigs, fee, signingKey.publicImage, sig, timestamp)
  }

  def create(w: HWallet,
             role: Role,
             depositAmount: Value,
             fee: Long,
             epochID: Long,
             boxesIdsToExclude: Seq[Array[Byte]] = Seq()): Try[RegisterTransaction] = Try {

    var s = 0L
    val to = Seq((TreasuryManager.DEPOSIT_ADDR, depositAmount))

    val from: IndexedSeq[(PrivateKey25519, Nonce, Value)] = w.boxes()
      .filter(b => !boxesIdsToExclude.exists(_ sameElements b.box.id)).sortBy(_.createdAt).takeWhile { b =>
      s = s + b.box.value
      s < depositAmount + b.box.value
    }.flatMap { b =>
      w.secretByPublicImage(b.box.proposition).map(s => (s, b.box.nonce, b.box.value))
    }.toIndexedSeq
    val canSend = from.map(_._3.toLong).sum
    require(canSend >= (depositAmount + fee))

    val charge: Seq[(PublicKey25519Proposition, Value)] =
      if (canSend > depositAmount + fee)
        Seq((w.publicKeys.head, Value @@ (canSend - depositAmount - fee)))
      else Seq()

    val inputs = from.map(t => t._1 -> t._2)
    val outputs: IndexedSeq[(PublicKey25519Proposition, Value)] = (to ++ charge).toIndexedSeq

    require(from.map(_._3.toLong).sum - outputs.map(_._2.toLong).sum == fee)

    val pubKey = w.generateNewTreasurySigningSecret(role, epochID)
    val privKey = w.treasurySigningSecretByPubKey(epochID, pubKey).get.privKey
    val timestamp = System.currentTimeMillis()

    RegisterTransaction(role, epochID, inputs, outputs, fee, privKey, timestamp)
  }
}

object RegisterTransactionCompanion extends Serializer[RegisterTransaction] {

  def toBytes(t: RegisterTransaction): Array[Byte] = {
    Bytes.concat(
      Array(t.role.id.toByte),
      Longs.toByteArray(t.epochID),
      t.pubKey.bytes,
      t.signature.bytes,
      SimpleBoxTransactionCompanion.toBytesCommonArgs(t))
  }

  def parseBytes(bytes: Array[Byte]): Try[RegisterTransaction] = Try {
    val role: Role = Role(bytes(0))
    val epochID = Longs.fromByteArray(bytes.slice(1,9))
    val pubKey = PublicKey25519Proposition(PublicKey @@ bytes.slice(9, Curve25519.KeyLength+9))
    var s = 9+Curve25519.KeyLength
    val sig = Signature25519(Signature @@ bytes.slice(s, s+Curve25519.SignatureLength))
    s = s + Curve25519.SignatureLength
    val (from, to, signatures, fee, timestamp) = SimpleBoxTransactionCompanion.parseBytesCommonArgs(bytes.drop(s)).get

    RegisterTransaction(role, epochID, from, to, signatures, fee, pubKey, sig, timestamp)
  }
}
