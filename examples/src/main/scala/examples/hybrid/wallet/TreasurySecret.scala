package examples.hybrid.wallet

import com.google.common.primitives.{Bytes, Ints, Longs}
import examples.hybrid.TreasuryManager
import examples.hybrid.TreasuryManager.Role
import examples.hybrid.TreasuryManager.Role.Role
import examples.hybrid.wallet.TreasurySecret.Type
import examples.hybrid.wallet.TreasurySecret.Type.Type
import scorex.core.serialization.Serializer
import scorex.core.transaction.state.{PrivateKey25519, PrivateKey25519Serializer}
import treasury.crypto.core.{PrivKey, PubKey}

import scala.util.{Failure, Success, Try}

/**
  * Structures for holding treasury secrets (specifically signing and proxy keys) in a wallet
  */

trait TreasurySecret {
  val epochId: Long
  val secretType: Type
}

object TreasurySecret {
  object Type extends Enumeration {
    type Type = Value
    val CommitteeSecret, SigningSecret = Value
  }
}

/**
  * Signing secret is basically a pair of keys that is used to sign treasury transactions. A public key of the pair is registered
  * with a special registration transaction at the beginning of each epoch
  * @param role Voter / Expert / Committee Member
  * @param privKey
  * @param epochId
  */
case class TreasurySigningSecret(role: Role, privKey: PrivateKey25519, override val epochId: Long) extends TreasurySecret {
  override val secretType = Type.SigningSecret
}

/**
  * Committee secret is a pair of keys that is used by committee member to maintain voting procedure. These keys are used for
  * distributed key generation, tally and etc. They could also be referred as "proxy key" throughout the documentation.
  * The public key of the pair is registered with a special CommitteeRegistrationTransaction at the beginning of each epoch.
  * @param privKey A private key (from transport key-pair) provided by treasury-crypto library
  * @param pubKey A public key (from transport key-pair) provided by treasury-crypto library
  * @param secretKey A secret key, which should be used for a shared public key generation in the DKG protocol
  * @param epochId ID of an epoch, in which the specified set of keys should be used
  */
case class TreasuryCommitteeSecret(privKey: PrivKey, pubKey: PubKey, secretKey: PrivKey, override val epochId: Long) extends TreasurySecret {
  override val secretType = Type.CommitteeSecret
}

object TreasurySecretSerializer extends Serializer[TreasurySecret] {

  def batchToBytes(batch: Seq[TreasurySecret]): Array[Byte] = {
    batch.foldLeft(Array[Byte]()) { case (acc, s) =>
      val bytes = toBytes(s)
      Bytes.concat(acc, Ints.toByteArray(bytes.length), bytes)
    }
  }

  @SuppressWarnings(Array("org.wartremover.warts.Recursion"))
  def parseBatch(bytes: Array[Byte]): List[TreasurySecret] =
    if (bytes.length < 4) List()
    else {
      val size = Ints.fromByteArray(bytes.slice(0,4))
      parseBytes(bytes.slice(4, size+4)) match {
        case Success(s) => s :: parseBatch(bytes.drop(size+4))
        case Failure(_) => parseBatch(bytes.drop(size+4))
      }
    }

  def toBytes(s: TreasurySecret): Array[Byte] = {
    s match {
      case s: TreasurySigningSecret => Bytes.concat(Array(s.secretType.id.toByte), TreasurySigningSecretSerializer.toBytes(s))
      case s: TreasuryCommitteeSecret => Bytes.concat(Array(s.secretType.id.toByte), TreasuryCommitteeSecretSerializer.toBytes(s))
    }
  }

  def parseBytes(bytes: Array[Byte]): Try[TreasurySecret] = Try {
    val secretType: Type = Type(bytes(0))
    secretType match {
      case t: Type if t == Type.CommitteeSecret => TreasuryCommitteeSecretSerializer.parseBytes(bytes.drop(1)).get
      case t: Type if t == Type.SigningSecret => TreasurySigningSecretSerializer.parseBytes(bytes.drop(1)).get
    }
  }
}

object TreasuryCommitteeSecretSerializer extends Serializer[TreasuryCommitteeSecret] {
  def toBytes(s: TreasuryCommitteeSecret): Array[Byte] = {
    val privBytes = s.privKey.toByteArray
    val pubBytes = s.pubKey.getEncoded(true)
    val secretBytes = s.secretKey.toByteArray
    Bytes.concat(
      Longs.toByteArray(s.epochId),
      Ints.toByteArray(privBytes.length),
      privBytes,
      Ints.toByteArray(pubBytes.length),
      pubBytes,
      Ints.toByteArray(secretBytes.length),
      secretBytes)
  }

  def parseBytes(bytes: Array[Byte]): Try[TreasuryCommitteeSecret] = Try {

    var offset = 0
    def offsetPlus (i: Int): Int = { offset += i; offset }

    val epochID    = Longs.fromByteArray(bytes.slice(offset, offsetPlus(8)))
    val privSize   = Ints.fromByteArray (bytes.slice(offset, offsetPlus(4)))
    val privKey    = new PrivKey        (bytes.slice(offset, offsetPlus(privSize)))
    val pubSize    = Ints.fromByteArray (bytes.slice(offset, offsetPlus(4)))
    val pubKey     = TreasuryManager.cs.decodePoint(bytes.slice(offset, offsetPlus(pubSize)))
    val secretSize = Ints.fromByteArray (bytes.slice(offset, offsetPlus(4)))
    val secretKey  = new PrivKey        (bytes.slice(offset, offsetPlus(secretSize)))

    TreasuryCommitteeSecret(privKey, pubKey, secretKey, epochID)
  }
}

object TreasurySigningSecretSerializer extends Serializer[TreasurySigningSecret] {
  def toBytes(s: TreasurySigningSecret): Array[Byte] = {
    Bytes.concat(
      Array(s.role.id.toByte),
      Longs.toByteArray(s.epochId),
      s.privKey.bytes)
  }

  def parseBytes(bytes: Array[Byte]): Try[TreasurySigningSecret] = Try {
    val role: Role = Role(bytes(0))
    val epochID = Longs.fromByteArray(bytes.slice(1,9))
    val pk = PrivateKey25519Serializer.parseBytes(bytes.drop(9)).get

    TreasurySigningSecret(role, pk, epochID)
  }
}
