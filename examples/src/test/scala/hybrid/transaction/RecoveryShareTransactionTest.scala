package hybrid.transaction

import examples.commons.SimpleBoxTransactionCompanion
import examples.hybrid.TreasuryManager
import examples.hybrid.transaction.{DecryptionShareTransaction, RecoveryShareTransaction}
import examples.hybrid.transaction.DecryptionShareTransaction.DecryptionRound
import examples.hybrid.transaction.RecoveryShareTransaction.OpenedShareWithId
import org.scalatest.FunSuite
import scorex.core.transaction.state.PrivateKey25519
import scorex.crypto.signatures.{PrivateKey, PublicKey}
import treasury.crypto.core.{HybridPlaintext, One, VoteCases}
import treasury.crypto.keygen.DecryptionManager
import treasury.crypto.keygen.datastructures.round4.OpenedShare
import treasury.crypto.voting.RegularVoter

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

    val txBytes = RecoveryShareTransaction.create(fakeKey, openedShares, 12).get.bytes
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