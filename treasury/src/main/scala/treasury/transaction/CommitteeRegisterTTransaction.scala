package treasury.transaction

import com.google.common.primitives.{Bytes, Ints, Longs}
import examples.commons.SimpleBoxTransaction
import examples.hybrid.wallet.HWallet
import scorex.core.serialization.Serializer
import scorex.core.transaction.proof.Signature25519
import scorex.core.transaction.state.{PrivateKey25519, PrivateKey25519Companion}
import scorex.crypto.signatures.{Curve25519, Signature}
import treasury.crypto.core.{Cryptosystem, KeyPair, PubKey}

import scala.util.Try

case class CommitteeRegisterTTransaction(committeePubKey: PubKey,
                                         override val signature: Signature25519,
                                         override val epochID: Long,
                                         override val blocksRangeToInclude: (Long, Long))
  extends RegisterTTransaction {

  override type M = CommitteeRegisterTTransaction

  override lazy val serializer = CommitteeRegisterCompanion

  override val messageToSign = {
    val keyBytes = committeePubKey.getEncoded(true)
    Bytes.concat(Ints.toByteArray(keyBytes.length),
      keyBytes,
      Longs.toByteArray(epochID),
      Longs.toByteArray(blocksRangeToInclude._1),
      Longs.toByteArray(blocksRangeToInclude._2))
  }

  override def json = ???
}

object CommitteeRegisterTTransaction {
  def apply(account: PrivateKey25519,
            committeePubKey: PubKey,
            epochID: Long,
            blocksRangeToInclude: (Long, Long)): CommitteeRegisterTTransaction = {

    val fakeSig = Signature25519(Signature @@ Array[Byte]())
    val fakeSigned = CommitteeRegisterTTransaction(committeePubKey, fakeSig, epochID, blocksRangeToInclude)

    val msg = fakeSigned.messageToSign
    val sig = PrivateKey25519Companion.sign(account, msg)

    new CommitteeRegisterTTransaction(committeePubKey, sig, epochID, blocksRangeToInclude)
  }

  def create(w: HWallet,
             epochID: Long,
             blocksRangeToInclude: (Long,Long)): Try[(CommitteeRegisterTTransaction, KeyPair)] = Try {
    val keyPair = new Cryptosystem().createKeyPair
    val acc = w.secretByPublicImage(w.boxes().head.box.proposition).get
    (CommitteeRegisterTTransaction(acc, keyPair._2, epochID, blocksRangeToInclude), keyPair)
  }
}

object CommitteeRegisterCompanion extends Serializer[CommitteeRegisterTTransaction] {
  def toBytes(t: CommitteeRegisterTTransaction): Array[Byte] = {
    val keyBytes = t.committeePubKey.getEncoded(true)
    Bytes.concat(
      Ints.toByteArray(keyBytes.length),
      keyBytes,
      t.signature.bytes,
      Longs.toByteArray(t.epochID),
      Longs.toByteArray(t.blocksRangeToInclude._1),
      Longs.toByteArray(t.blocksRangeToInclude._2)
    )
  }

  def parseBytes(bytes: Array[Byte]): Try[CommitteeRegisterTTransaction] = Try {
    val keySize = Ints.fromByteArray(bytes.slice(0,4))
    val committeePubKey = new Cryptosystem().decodePoint(bytes.slice(4,keySize))
    val signature = Signature25519(Signature @@ bytes.slice(4+keySize, 4+keySize+Curve25519.SignatureLength))
    val s = 4+keySize+Curve25519.SignatureLength
    val epochID = Longs.fromByteArray(bytes.slice(s,s+8))
    val blocksRangeToInclude = (Longs.fromByteArray(bytes.slice(s+8,s+16)), Longs.fromByteArray(bytes.slice(s+16,s+24)))

    CommitteeRegisterTTransaction(committeePubKey, signature, epochID, blocksRangeToInclude)
  }
}
