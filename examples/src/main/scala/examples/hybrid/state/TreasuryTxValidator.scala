package examples.hybrid.state

import examples.commons.{SimpleBoxTransaction, SimpleBoxTx}
import examples.hybrid.TreasuryManager
import examples.hybrid.TreasuryManager.Role
import examples.hybrid.transaction.BallotTransaction.VoterType
import examples.hybrid.transaction._
import treasury.crypto.core.One
import treasury.crypto.voting.ballots.{ExpertBallot, VoterBallot}
import treasury.crypto.voting.{Expert, RegularVoter, Voter}

import scala.util.{Success, Try}

class TreasuryTxValidator(val trState: TreasuryState, val height: Long) {

  val epochHeight = height - (trState.epochNum * TreasuryManager.EPOCH_LEN)
  require(epochHeight >= 0 && epochHeight < TreasuryManager.EPOCH_LEN, "Totally wrong situation. Probably treasury state is corrupted or problems with validation pipeline.")

  def validate(tx: SimpleBoxTransaction): Try[Unit] = tx match {
      case t: TreasuryTransaction => validate(t)
      case _: SimpleBoxTx => Success(Unit)
  }

  def validate(tx: TreasuryTransaction): Try[Unit] = Try {
    /* Common checks for all treasury txs */
    require(tx.epochID == trState.epochNum, "Invalid tx: wrong epoch id")

    /* Checks for specific treasury txs */
    tx match {
      case t: RegisterTransaction => validateRegistration(t).get
      case t: CommitteeRegisterTransaction => validateCommitteeRegistration(t).get
      case t: ProposalTransaction => validateProposal(t).get
      case t: BallotTransaction => validateBallot(t).get
    }
  }

  def validateRegistration(tx: RegisterTransaction): Try[Unit] = Try {
    require(TreasuryManager.REGISTER_RANGE.contains(epochHeight), "Wrong height for register transaction")

    tx.role match {
      case Role.Expert => require(!trState.getExpertsSigningKeys.contains(tx.pubKey), "Expert pubkey has been already registered")
      case Role.Voter => require(!trState.getVotersSigningKeys.contains(tx.pubKey), "Voter pubkey has been already registered")
    }

    // TODO: check that transaction makes a necessary deposit. Probably there should be some special type of time-locked box.
    // tx.to.foreach()
  }

  def validateCommitteeRegistration(tx: CommitteeRegisterTransaction): Try[Unit] = Try {
    require(TreasuryManager.REGISTER_RANGE.contains(epochHeight), "Wrong height for register transaction")

    require(!trState.getCommitteeSigningKeys.contains(tx.pubKey), "Committee signing pubkey has been already registered")
    require(!trState.getCommitteeProxyKeys.contains(tx.proxyPubKey), "Committee proxy pubkey has been already registered")

    // TODO: check that transaction makes a necessary deposit. Probably there should be some special type of time-locked box.
    // tx.to.foreach()
  }

  def validateProposal(tx: ProposalTransaction): Try[Unit] = Try {
    require(TreasuryManager.PROPOSAL_SUBMISSION_RANGE.contains(epochHeight), "Wrong height for proposal transaction")
    // TODO: add validation
  }

  def validateBallot(tx: BallotTransaction): Try[Unit] = Try {
    require(TreasuryManager.VOTING_RANGE.contains(epochHeight), "Wrong height for ballot transaction")
    require(trState.getSharedPubKey.isDefined, "Shared key is not defined in TreasuryState")
    require(trState.getProposals.nonEmpty, "Proposals are not defined")

    tx.voterType match {
      case VoterType.Voter =>
        val id = trState.getVotersSigningKeys.indexOf(tx.pubKey)
        require(id >= 0, "Voter is not registered")
        require(trState.getVotersBallots.contains(id) == false, "The voter has already voted")
        tx.ballots.foreach(b => require(b.isInstanceOf[VoterBallot], "Incompatible ballot"))
        val expertsNum = trState.getExpertsSigningKeys.size
        val voter = new RegularVoter(TreasuryManager.cs, expertsNum, trState.getSharedPubKey.get, One)
        tx.ballots.foreach { b =>
          require(b.unitVector.length == expertsNum + Voter.VOTER_CHOISES_NUM)
          require(voter.verifyBallot(b), "Ballot NIZK is not verified")}

      case VoterType.Expert =>
        val id = trState.getExpertsSigningKeys.indexOf(tx.pubKey)
        require(id >= 0, "Expert is not registered")
        require(trState.getExpertsBallots.contains(id) == false, "The expert has already voted")
        tx.ballots.foreach(b => require(b.isInstanceOf[ExpertBallot], "Incompatible ballot"))
        val expert = new Expert(TreasuryManager.cs, id, trState.getSharedPubKey.get)
        tx.ballots.foreach { b =>
          require(b.unitVector.length == Voter.VOTER_CHOISES_NUM)
          require(b.asInstanceOf[ExpertBallot].expertId == id, "Wrong expertId in a ballot")
          require(expert.verifyBallot(b), "Ballot NIZK is not verified")}
    }

    require(trState.getProposals.size == tx.ballots.size, "Number of ballots isn't equal to the number of proposals")
    trState.getProposals.indices.foreach(i =>
      require(tx.ballots.find(p => p.proposalId == i).isDefined, s"No ballot for proposal ${i}"))
  }
}
