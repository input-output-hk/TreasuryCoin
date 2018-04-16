package hybrid.transaction

import examples.commons.SimpleBoxTransactionCompanion
import examples.hybrid.TreasuryManager
import examples.hybrid.transaction.committee.RecoveryShareTransaction
import examples.hybrid.transaction.committee.RecoveryShareTransaction.{OpenedShareWithId, RecoveryRound}
import org.scalatest.FunSuite
import scorex.core.transaction.state.PrivateKey25519
import scorex.crypto.signatures.{PrivateKey, PublicKey}
import treasury.crypto.core.HybridPlaintext
import treasury.crypto.keygen.datastructures.round4.OpenedShare

class RecoveryShareTransactionTest extends FunSuite {

  val cs = TreasuryManager.cs
  val (privKey, pubKey) = cs.createKeyPair

  val plaintext = HybridPlaintext(pubKey, Array(1.toByte, 2.toByte))
  val openedShares = Array(
    OpenedShareWithId(1, OpenedShare(0, plaintext)),
    OpenedShareWithId(33, OpenedShare(0, plaintext))
  )

  test("serialization") {
    val fakeKey = PrivateKey25519(PrivateKey @@ Array.fill[Byte](32)(1.toByte), PublicKey @@ Array.fill[Byte](32)(1.toByte))

    val txBytes = RecoveryShareTransaction.create(fakeKey, RecoveryRound.DecryptionR1, openedShares, 12).get.bytes
    val tx = SimpleBoxTransactionCompanion.parseBytes(txBytes).get.asInstanceOf[RecoveryShareTransaction]

    assert(tx.semanticValidity.isFailure)
    assert(tx.openedShares(0).violatorId == 1)
    assert(tx.openedShares(1).violatorId == 33)
    assert(tx.openedShares(0).openedShare.bytes sameElements openedShares(0).openedShare.bytes)
    assert(tx.openedShares(1).openedShare.bytes sameElements openedShares(1).openedShare.bytes)
    assert(tx.pubKey == fakeKey.publicImage)
    assert(tx.epochID == 12)
  }
}