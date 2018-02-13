package hybrid.transaction

import examples.commons.SimpleBoxTransactionCompanion
import examples.hybrid.TreasuryManager
import examples.hybrid.transaction.{BallotTransaction, DecryptionShareTransaction}
import examples.hybrid.transaction.BallotTransaction.VoterType
import examples.hybrid.transaction.DecryptionShareTransaction.DecryptionRound
import org.scalatest.FunSuite
import scorex.core.transaction.state.PrivateKey25519
import scorex.crypto.signatures.{PrivateKey, PublicKey}
import treasury.crypto.core.{One, VoteCases}
import treasury.crypto.keygen.DecryptionManager
import treasury.crypto.voting.RegularVoter

class DecryptionTransactionTest extends FunSuite {

  val cs = TreasuryManager.cs
  val (privKey, pubKey) = cs.createKeyPair

  val numberOfExperts = 6
  val voter = new RegularVoter(cs, numberOfExperts, pubKey, One)
  val ballots = Array(voter.produceVote(0, VoteCases.Abstain), voter.produceVote(1, VoteCases.Abstain))

  val decryptor = new DecryptionManager(cs, ballots, 1)
  val c1Shares = Array(decryptor.decryptC1ForDelegations(0, 0, privKey),
                  decryptor.decryptC1ForDelegations(1, 0, privKey))

  test("serialization") {
    val fakeKey = PrivateKey25519(PrivateKey @@ Array.fill[Byte](32)(1.toByte), PublicKey @@ Array.fill[Byte](32)(1.toByte))

    val txBytes = DecryptionShareTransaction.create(fakeKey, DecryptionRound.R2, c1Shares, 12).get.bytes
    val tx = SimpleBoxTransactionCompanion.parseBytes(txBytes).get.asInstanceOf[DecryptionShareTransaction]

    assert(tx.semanticValidity.isFailure)
    assert(decryptor.validateDelegationsC1(pubKey, tx.c1Shares(0)).isSuccess)
    assert(decryptor.validateDelegationsC1(pubKey, tx.c1Shares(1)).isSuccess)
    assert(tx.c1Shares(0).issuerID == 0)
    assert(tx.c1Shares(1).issuerID == 1)
    assert(tx.c1Shares(1).proposalId == 0)
    assert(tx.pubKey == fakeKey.publicImage)
    assert(tx.round == DecryptionRound.R2)
    assert(tx.epochID == 12)
  }
}
