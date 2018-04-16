package examples.hybrid.transaction.committee.DKG

import com.google.common.primitives.{Bytes, Ints, Longs}
import examples.commons.{SimpleBoxTransaction, SimpleBoxTransactionCompanion}
import examples.hybrid.TreasuryManager
import examples.hybrid.transaction.{DKGr3TxTypeId, SignedTreasuryTransaction}
import io.circe.Json
import io.circe.syntax._
import scorex.core.ModifierTypeId
import scorex.core.serialization.Serializer
import scorex.core.transaction.box.proposition.PublicKey25519Proposition
import scorex.core.transaction.proof.Signature25519
import scorex.core.transaction.state.{PrivateKey25519, PrivateKey25519Companion}
import scorex.crypto.encode.Base58
import scorex.crypto.signatures.{Curve25519, PublicKey, Signature}
import treasury.crypto.keygen.datastructures.round3.{R3Data, R3DataSerializer}

import scala.util.Try

case class DKGr3Transaction( r3Data: R3Data,
                             override val epochID: Long,
                             override val pubKey: PublicKey25519Proposition, // previously registered committee public key
                             override val signature: Signature25519,
                             override val timestamp: Long) extends SignedTreasuryTransaction(timestamp) {

  override type M = SimpleBoxTransaction

  override val transactionTypeId: ModifierTypeId = DKGr3Transaction.TransactionTypeId

  override val serializer = SimpleBoxTransactionCompanion

  override lazy val messageToSign = {
    val superBytes = Bytes.concat(if (newBoxes.nonEmpty) scorex.core.utils.concatBytes(newBoxes.map(_.bytes)) else Array[Byte](),
      scorex.core.utils.concatFixLengthBytes(unlockers.map(_.closedBoxId)),
      Longs.toByteArray(timestamp),
      Longs.toByteArray(fee))

    Bytes.concat(
      pubKey.bytes,
      r3Data.bytes,
      Longs.toByteArray(epochID),
      superBytes)
  }

  override lazy val json: Json = Map("id" -> Base58.encode(id).asJson).asJson //TODO

  override lazy val semanticValidity: Try[Unit] = Try {
    require(timestamp >= 0)
    require(signature.isValid(pubKey, messageToSign))
  }

  override def toString: String = s"DKGr3Transaction (${json.noSpaces})"
}

object DKGr3Transaction {

  val TransactionTypeId: scorex.core.ModifierTypeId = DKGr3TxTypeId

  def create(privKey: PrivateKey25519,
             r3Data: R3Data,
             epochID: Long): Try[DKGr3Transaction] = Try {
    val timestamp = System.currentTimeMillis()
    val fakeSig = Signature25519(Signature @@ Array[Byte]())
    val unsigned = DKGr3Transaction(r3Data, epochID, privKey.publicImage, fakeSig, timestamp)
    val sig = PrivateKey25519Companion.sign(privKey, unsigned.messageToSign)

    DKGr3Transaction(r3Data, epochID, privKey.publicImage, sig, timestamp)
  }
}

object DKGr3TransactionCompanion extends Serializer[DKGr3Transaction] {

  def toBytes(t: DKGr3Transaction): Array[Byte] = {

    Bytes.concat(
      Ints.toByteArray(t.r3Data.size),
      t.r3Data.bytes,
      Longs.toByteArray(t.epochID),
      t.pubKey.bytes,
      t.signature.bytes,
      Longs.toByteArray(t.timestamp)
    )
  }

  def parseBytes(bytes: Array[Byte]): Try[DKGr3Transaction] = Try {

    var offset = 0
    def offsetPlus (i: Int): Int = { offset += i; offset }

    val r3DataSize = Ints.fromByteArray(bytes.slice(offset, offsetPlus(4)))

    val r3Data = R3DataSerializer.parseBytes(bytes.slice(offset, offsetPlus(r3DataSize)), TreasuryManager.cs).get

    val epochID = Longs.fromByteArray(bytes.slice(offset, offsetPlus(8)))

    val pubKey = PublicKey25519Proposition(PublicKey @@ bytes.slice(offset, offsetPlus(Curve25519.KeyLength)))

    val sig = Signature25519(Signature @@ bytes.slice(offset, offsetPlus(Curve25519.SignatureLength)))

    val timestamp = Longs.fromByteArray(bytes.slice(offset, offsetPlus(8)))

    DKGr3Transaction(r3Data, epochID, pubKey, sig, timestamp)
  }
}

