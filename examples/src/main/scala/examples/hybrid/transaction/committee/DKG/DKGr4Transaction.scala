package examples.hybrid.transaction.committee.DKG

import com.google.common.primitives.{Bytes, Ints, Longs}
import examples.commons.{SimpleBoxTransaction, SimpleBoxTransactionCompanion}
import examples.hybrid.TreasuryManager
import examples.hybrid.transaction.{DKGr4TxTypeId, SignedTreasuryTransaction}
import io.circe.Json
import io.circe.syntax._
import scorex.core.ModifierTypeId
import scorex.core.serialization.Serializer
import scorex.core.transaction.box.proposition.PublicKey25519Proposition
import scorex.core.transaction.proof.Signature25519
import scorex.core.transaction.state.{PrivateKey25519, PrivateKey25519Companion}
import scorex.crypto.encode.Base58
import scorex.crypto.signatures.{Curve25519, PublicKey, Signature}
import treasury.crypto.keygen.datastructures.round4.{R4Data, R4DataSerializer}

import scala.util.Try

case class DKGr4Transaction( r4Data: R4Data,
                             override val epochID: Long,
                             override val pubKey: PublicKey25519Proposition, // previously registered committee public key
                             override val signature: Signature25519,
                             override val timestamp: Long) extends SignedTreasuryTransaction(timestamp) {

  override type M = SimpleBoxTransaction

  override val transactionTypeId: ModifierTypeId = DKGr4Transaction.TransactionTypeId

  override val serializer = SimpleBoxTransactionCompanion

  override lazy val messageToSign = {
    val superBytes = Bytes.concat(if (newBoxes.nonEmpty) scorex.core.utils.concatBytes(newBoxes.map(_.bytes)) else Array[Byte](),
      scorex.core.utils.concatFixLengthBytes(unlockers.map(_.closedBoxId)),
      Longs.toByteArray(timestamp),
      Longs.toByteArray(fee))

    Bytes.concat(
      pubKey.bytes,
      r4Data.bytes,
      Longs.toByteArray(epochID),
      superBytes)
  }

  override lazy val json: Json = Map("id" -> Base58.encode(id).asJson).asJson //TODO

  override lazy val semanticValidity: Try[Unit] = Try {
    require(timestamp >= 0)
    require(signature.isValid(pubKey, messageToSign))
  }

  override def toString: String = s"DKGr4Transaction (${json.noSpaces})"
}

object DKGr4Transaction {

  val TransactionTypeId: scorex.core.ModifierTypeId = DKGr4TxTypeId

  def create(privKey: PrivateKey25519,
             r4Data: R4Data,
             epochID: Long): Try[DKGr4Transaction] = Try {
    val timestamp = System.currentTimeMillis()
    val fakeSig = Signature25519(Signature @@ Array[Byte]())
    val unsigned = DKGr4Transaction(r4Data, epochID, privKey.publicImage, fakeSig, timestamp)
    val sig = PrivateKey25519Companion.sign(privKey, unsigned.messageToSign)

    DKGr4Transaction(r4Data, epochID, privKey.publicImage, sig, timestamp)
  }
}

object DKGr4TransactionCompanion extends Serializer[DKGr4Transaction] {

  def toBytes(t: DKGr4Transaction): Array[Byte] = {

    Bytes.concat(
      Ints.toByteArray(t.r4Data.size),
      t.r4Data.bytes,
      Longs.toByteArray(t.epochID),
      t.pubKey.bytes,
      t.signature.bytes,
      Longs.toByteArray(t.timestamp)
    )
  }

  def parseBytes(bytes: Array[Byte]): Try[DKGr4Transaction] = Try {

    var offset = 0
    def offsetPlus (i: Int): Int = { offset += i; offset }

    val r4DataSize = Ints.fromByteArray(bytes.slice(offset, offsetPlus(4)))

    val r4Data = R4DataSerializer.parseBytes(bytes.slice(offset, offsetPlus(r4DataSize)), TreasuryManager.cs).get

    val epochID = Longs.fromByteArray(bytes.slice(offset, offsetPlus(8)))

    val pubKey = PublicKey25519Proposition(PublicKey @@ bytes.slice(offset, offsetPlus(Curve25519.KeyLength)))

    val sig = Signature25519(Signature @@ bytes.slice(offset, offsetPlus(Curve25519.SignatureLength)))

    val timestamp = Longs.fromByteArray(bytes.slice(offset, offsetPlus(8)))

    DKGr4Transaction(r4Data, epochID, pubKey, sig, timestamp)
  }
}

