package examples.hybrid.transaction

import com.google.common.primitives.{Bytes, Ints, Longs}
import examples.hybrid.TreasuryManager
import examples.hybrid.wallet.HWallet
import io.circe.Json
import io.circe.syntax._
import io.iohk.iodb.ByteArrayWrapper
import scorex.core.ModifierTypeId
import scorex.core.serialization.Serializer
import scorex.core.transaction.proof.Signature25519
import scorex.core.transaction.state.{PrivateKey25519, PrivateKey25519Companion}
import scorex.crypto.encode.Base58
import scorex.crypto.signatures.{Curve25519, Signature}
import treasury.crypto.core.{Cryptosystem, KeyPair, PubKey}

import scala.util.Try

case class CommitteeRegisterTx(committeePubKey: PubKey,
                               override val signature: Signature25519,
                               override val epochID: Long,
                               override val blocksRangeToInclude: (Long, Long),
                               override val timestamp: Long)
  extends RegisterTTransaction(0L) {

  override type M = CommitteeRegisterTx

  override val modifierTypeId: ModifierTypeId = CommitteeRegisterTx.ModifierTypeId

  override val serializer = CommitteeRegisterTxCompanion

  override lazy val messageToSign = {
    val keyBytes = committeePubKey.getEncoded(true)
    Bytes.concat(Ints.toByteArray(keyBytes.length),
      keyBytes,
      Longs.toByteArray(epochID),
      Longs.toByteArray(blocksRangeToInclude._1),
      Longs.toByteArray(blocksRangeToInclude._2))
  }

  override lazy val json: Json = Map("id" -> Base58.encode(id).asJson).asJson //TODO

  override lazy val semanticValidity: Try[Unit] = Try(Unit)

  override def toString: String = s"CommitteeRegisterTx(${json.noSpaces})"
}

object CommitteeRegisterTx {
  val ModifierTypeId: scorex.core.ModifierTypeId = CommitteeRegisterTxTypeId

  def apply(account: PrivateKey25519,
            committeePubKey: PubKey,
            epochID: Long,
            blocksRangeToInclude: (Long, Long),
            timestamp: Long): CommitteeRegisterTx = {

    val fakeSig = Signature25519(Signature @@ Array[Byte]())
    val fakeSigned = CommitteeRegisterTx(committeePubKey, fakeSig, epochID, blocksRangeToInclude, timestamp)

    val msg = fakeSigned.messageToSign
    val sig = PrivateKey25519Companion.sign(account, msg)

    new CommitteeRegisterTx(committeePubKey, sig, epochID, blocksRangeToInclude, timestamp)
  }

  def create(w: HWallet,
             epochID: Long,
             blocksRangeToInclude: (Long,Long)): Try[(CommitteeRegisterTx, KeyPair)] = Try {
    val keyPair = new Cryptosystem().createKeyPair
    val acc = w.secretByPublicImage(w.boxes().head.box.proposition).get
    val timestamp = System.currentTimeMillis()
    (CommitteeRegisterTx(acc, keyPair._2, epochID, blocksRangeToInclude, timestamp), keyPair)
  }
}

object CommitteeRegisterTxCompanion extends Serializer[CommitteeRegisterTx] {
  def toBytes(t: CommitteeRegisterTx): Array[Byte] = {
    val keyBytes = t.committeePubKey.getEncoded(true)
    Bytes.concat(
      Ints.toByteArray(keyBytes.length),
      keyBytes,
      t.signature.bytes,
      Longs.toByteArray(t.epochID),
      Longs.toByteArray(t.blocksRangeToInclude._1),
      Longs.toByteArray(t.blocksRangeToInclude._2),
      Longs.toByteArray(t.timestamp)
    )
  }

  def parseBytes(bytes: Array[Byte]): Try[CommitteeRegisterTx] = Try {
    val keySize = Ints.fromByteArray(bytes.slice(0,4))
    val committeePubKey = TreasuryManager.cs.decodePoint(bytes.slice(4,keySize+4))
    val signature = Signature25519(Signature @@ bytes.slice(4+keySize, 4+keySize+Curve25519.SignatureLength))
    val s = 4+keySize+Curve25519.SignatureLength
    val epochID = Longs.fromByteArray(bytes.slice(s,s+8))
    val blocksRangeToInclude = (Longs.fromByteArray(bytes.slice(s+8,s+16)), Longs.fromByteArray(bytes.slice(s+16,s+24)))
    val timestamp = Longs.fromByteArray(bytes.slice(s+24,s+32))

    CommitteeRegisterTx(committeePubKey, signature, epochID, blocksRangeToInclude, timestamp)
  }
}
