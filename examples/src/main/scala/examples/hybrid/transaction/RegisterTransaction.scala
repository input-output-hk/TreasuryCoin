package examples.hybrid.transaction

import com.google.common.primitives.{Booleans, Bytes, Ints, Longs}
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
import treasury.crypto.core.PubKey

import scala.util.Try

/**
  * A united Register transaction for Voter/Expert and Committee member. Note that only voter or expert can apply to be
  * a committee member. In this case committeeProxyPubKey should be defined and additional deposit should be added to tx
  *
  * @param role voter or expert
  * @param paybackAddr an addr where all rewards (both voters/committee) and deposit will be sent
  * @param committeeProxyPubKey If a voter/expert wants to be a CM, he should define this key
  * @param epochID
  * @param from used outputs
  * @param to There should be special addresses of deposit accounts
  * @param signatures signatures for 'from' outputs
  * @param fee
  * @param pubKey signing key
  * @param signature signature for pubKey
  * @param timestamp
  */
case class RegisterTransaction(role: Role,
                               paybackAddr: PublicKey25519Proposition,
                               committeeProxyPubKey: Option[PubKey],
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
      paybackAddr.bytes,
      committeeProxyPubKey.map(_.getEncoded(true)).getOrElse(Array()),
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
            paybackAddr: PublicKey25519Proposition,
            committeeProxyPubKey: Option[PubKey],
            epochId: Long,
            from: IndexedSeq[(PrivateKey25519, Nonce)],
            to: IndexedSeq[(PublicKey25519Proposition, Value)],
            fee: Long,
            signingKey: PrivateKey25519,
            timestamp: Long): RegisterTransaction = {
    val fromPub = from.map { case (pr, n) => pr.publicImage -> n }
    val fakeSig = Signature25519(Signature @@ Array[Byte]())
    val fakeSigs = from.map(_ => fakeSig)

    val unsigned = RegisterTransaction(role, paybackAddr, committeeProxyPubKey, epochId, fromPub, to, fakeSigs, fee, signingKey.publicImage, fakeSig, timestamp)

    val msg = unsigned.messageToSign
    val sigs = from.map { case (priv, _) => PrivateKey25519Companion.sign(priv, msg) }
    val sig = PrivateKey25519Companion.sign(signingKey, unsigned.messageToSign)

    RegisterTransaction(role, paybackAddr, committeeProxyPubKey, epochId, fromPub, to, sigs, fee, signingKey.publicImage, sig, timestamp)
  }

  def create(w: HWallet,
             role: Role,
             depositAmount: Value,
             isCommittee: Boolean,
             fee: Long,
             epochID: Long,
             boxesIdsToExclude: Seq[Array[Byte]] = Seq()): Try[RegisterTransaction] = Try {
    require(role == Role.Voter || role == Role.Expert)

    var to = Seq((TreasuryManager.VOTER_DEPOSIT_ADDR, depositAmount))
    if (isCommittee)
      to = to :+ (TreasuryManager.COMMITTEE_DEPOSIT_ADDR, Value @@ TreasuryManager.COMMITTEE_DEPOSIT_RANGE.start.toLong)

    val (inputs, outputs) = w.prepareOutputs(to, fee, boxesIdsToExclude).get
    val paybackAddr = w.publicKeys.headOption.get

    val committeeKeyOpt = if (isCommittee) {
      Some(w.generateNewTreasuryCommitteeSecret(epochID))
    } else None

    val pubKey = w.generateNewTreasurySigningSecret(role, epochID)
    val privKey = w.treasurySigningSecretByPubKey(epochID, pubKey).get.privKey
    val timestamp = System.currentTimeMillis()

    RegisterTransaction(role, paybackAddr, committeeKeyOpt, epochID, inputs, outputs, fee, privKey, timestamp)
  }
}

object RegisterTransactionCompanion extends Serializer[RegisterTransaction] {

  def toBytes(t: RegisterTransaction): Array[Byte] = {
    val (isCommittee, keyLenOpt, keyBytesOpt) =
      if (t.committeeProxyPubKey.isDefined) {
        val keyBytes = t.committeeProxyPubKey.get.getEncoded(true)
        (1.toByte, Some(keyBytes.length), Some(keyBytes))
      } else (0.toByte, None, None)

    Bytes.concat(
      Array(t.role.id.toByte),
      Longs.toByteArray(t.epochID),
      t.paybackAddr.bytes,
      Array(isCommittee),
      keyLenOpt.map(Ints.toByteArray(_)).getOrElse(Array()),
      keyBytesOpt.getOrElse(Array()),
      t.pubKey.bytes,
      t.signature.bytes,
      SimpleBoxTransactionCompanion.toBytesCommonArgs(t))
  }

  def parseBytes(bytes: Array[Byte]): Try[RegisterTransaction] = Try {
    val role: Role = Role(bytes(0))
    val epochID = Longs.fromByteArray(bytes.slice(1,9))
    val paybackAddr = PublicKey25519Proposition(PublicKey @@ bytes.slice(9, Curve25519.KeyLength+9))
    var s = 9+Curve25519.KeyLength

    val committeeKeyOpt = if (bytes(s) == 1) {
      val keyLen = Ints.fromByteArray(bytes.slice(s+1,s+5))
      val key = TreasuryManager.cs.decodePoint(bytes.slice(s+5,s+5+keyLen))
      s += 4 + keyLen
      Some(key)
    } else None
    s += 1

    val pubKey = PublicKey25519Proposition(PublicKey @@ bytes.slice(s, s + Curve25519.KeyLength))
    s = s + Curve25519.KeyLength
    val sig = Signature25519(Signature @@ bytes.slice(s, s+Curve25519.SignatureLength))
    s = s + Curve25519.SignatureLength
    val (from, to, signatures, fee, timestamp) = SimpleBoxTransactionCompanion.parseBytesCommonArgs(bytes.drop(s)).get

    RegisterTransaction(role, paybackAddr, committeeKeyOpt, epochID, from, to, signatures, fee, pubKey, sig, timestamp)
  }
}
