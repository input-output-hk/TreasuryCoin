package hybrid.transaction

import examples.commons.SimpleBoxTransactionCompanion
import examples.hybrid.TreasuryManager
import examples.hybrid.transaction.BallotTransaction
import examples.hybrid.transaction.BallotTransaction.VoterType
import org.scalatest.FunSuite
import scorex.core.transaction.state.PrivateKey25519
import scorex.crypto.signatures.{PrivateKey, PublicKey}
import treasury.crypto.core.{One, VoteCases}
import treasury.crypto.voting.RegularVoter

class BallotTransactionTest extends FunSuite {

  val cs = TreasuryManager.cs
  val (privKey, pubKey) = cs.createKeyPair

  test("serialization") {
    val numberOfExperts = 6
    val voter = new RegularVoter(cs, numberOfExperts, pubKey, One)
    val ballot = voter.produceVote(0, VoteCases.Abstain)
    val ballot2 = voter.produceVote(1, VoteCases.Abstain)
    val fakeKey = PrivateKey25519(PrivateKey @@ Array.fill[Byte](32)(1.toByte), PublicKey @@ Array.fill[Byte](32)(1.toByte))

    val txBytes = BallotTransaction.create(fakeKey, VoterType.Voter, Seq(ballot,ballot2), 12).get.bytes
    val tx = SimpleBoxTransactionCompanion.parseBytes(txBytes).get.asInstanceOf[BallotTransaction]

    assert(tx.semanticValidity.isFailure)
    assert(voter.verifyBallot(tx.ballots(0)))
    assert(tx.ballots(0).proposalId == 0)
    assert(voter.verifyBallot(tx.ballots(1)))
    assert(tx.ballots(1).proposalId == 1)
    assert(tx.pubKey == fakeKey.publicImage)
    assert(tx.voterType == VoterType.Voter)
    assert(tx.epochID == 12)
  }
}
