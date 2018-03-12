package examples.hybrid.state

import examples.commons.{SimpleBoxTransaction, SimpleBoxTx}
import examples.hybrid.TreasuryManager
import examples.hybrid.TreasuryManager.Role
import examples.hybrid.transaction.BallotTransaction.VoterType
import examples.hybrid.transaction.DKG._
import examples.hybrid.transaction.DecryptionShareTransaction.DecryptionRound
import examples.hybrid.transaction._
import scorex.core.utils.ScorexLogging
import treasury.crypto.core.One
import treasury.crypto.keygen.DecryptionManager
import treasury.crypto.voting.ballots.{ExpertBallot, VoterBallot}
import treasury.crypto.voting.{Expert, RegularVoter, Voter}

import scala.util.{Failure, Success, Try}

class TreasuryTxValidator(val trState: TreasuryState, val height: Long) extends ScorexLogging {

  val epochHeight = height - (trState.epochNum * TreasuryManager.EPOCH_LEN)

  Try(require(epochHeight >= 0 && epochHeight < TreasuryManager.EPOCH_LEN,
    s"Totally wrong situation. Probably treasury state is corrupted or problems with " +
      s"validation pipeline. Height = $height, epochHeight = $epochHeight")) match {
    case Failure(e) =>
      log.error("Inconsistent height in TreasuryTxValidator", e)
      throw e
    case Success(_) =>
  }

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
      case t: DecryptionShareTransaction => validateDecryptionShare(t).get
      case t: DKGr1Transaction => validateDKGTransaction(t).get //validateDKGr1Transaction(t).get
      case t: DKGr2Transaction => validateDKGTransaction(t).get //validateDKGr1Transaction(t).get
      case t: DKGr3Transaction => validateDKGTransaction(t).get
      case t: DKGr4Transaction => validateDKGTransaction(t).get
      case t: DKGr5Transaction => validateDKGTransaction(t).get
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

  def validateDecryptionShare(tx: DecryptionShareTransaction): Try[Unit] = Try {
    require(trState.getSharedPubKey.isDefined, "Shared key is not defined in TreasuryState")
    require(trState.getProposals.nonEmpty, "Proposals are not defined")

    val id = trState.getCommitteeSigningKeys.indexOf(tx.pubKey)
    require(id >= 0, "Committee member isn't registered")

    require(trState.getProposals.size == tx.c1Shares.size, "Number of decryption shares isn't equal to the number of proposals")
    trState.getProposals.indices.foreach(i =>
      require(tx.c1Shares.find(s => s.proposalId == i).isDefined, s"No C1Share for proposal ${i}"))

    tx.round match {
      case DecryptionRound.R1 => validateDecryptionShareR1(tx).get
      case DecryptionRound.R2 => validateDecryptionShareR2(tx).get
    }
  }

  def validateDecryptionShareR1(tx: DecryptionShareTransaction): Try[Unit] = Try {
    require(TreasuryManager.VOTING_DECRYPTION_R1_RANGE.contains(epochHeight), "Wrong height for decryption share R1 transaction")
    require(tx.round == DecryptionRound.R1, "Invalid decryption share R1: wrong round")

    val id = trState.getCommitteeSigningKeys.indexOf(tx.pubKey)
    require(!trState.getDecryptionSharesR1.contains(id), "The committee member has already submitted decryption shares R1")

    val expertsNum = trState.getExpertsSigningKeys.size
    tx.c1Shares.foreach { s =>
      require(s.decryptedC1.size == expertsNum, "Invalid decryption share R1: wrong number of decrypted c1 componenets")
      val validator = new DecryptionManager(TreasuryManager.cs, trState.getBallotsForProposal(s.proposalId))
      require(validator.validateDelegationsC1(trState.getCommitteeProxyKeys(id), s).isSuccess, "Invalid decryption share R1: NIZK is not verified")
    }
  }

  def validateDecryptionShareR2(tx: DecryptionShareTransaction): Try[Unit] = Try {
    require(TreasuryManager.VOTING_DECRYPTION_R2_RANGE.contains(epochHeight), "Wrong height for decryption share R2 transaction")
    require(tx.round == DecryptionRound.R2, "Invalid decryption share R2: wrong round")
    require(trState.getDelegations.isDefined, "Delegations are not defined, decryption share R2 can't be validated")

    val id = trState.getCommitteeSigningKeys.indexOf(tx.pubKey)
    require(!trState.getDecryptionSharesR2.contains(id), "The committee member has already submitted decryption shares R2")

    tx.c1Shares.foreach { s =>
      require(s.decryptedC1.size == Voter.VOTER_CHOISES_NUM, "Invalid decryption share R2: wrong number of decrypted c1 componenets")
      val validator = new DecryptionManager(TreasuryManager.cs, trState.getBallotsForProposal(s.proposalId))
      require(validator.validateChoicesC1(trState.getCommitteeProxyKeys(id), s, trState.getDelegations.get(s.proposalId)).isSuccess,
        "Invalid decryption share R2: NIZK is not verified")
    }
  }

//  def validateDKGr1Transaction(tx: DKGr1Transaction): Try[Unit] = Try {
//    require(TreasuryManager.DISTR_KEY_GEN_R1_RANGE.contains(epochHeight), "Wrong height for DKG R1 transaction")
//
//    val id = trState.getCommitteeSigningKeys.indexOf(tx.pubKey)
//    require(id >= 0, "Committee member isn't found")
//    require(!trState.getDKGr1Data.contains(id), "The committee member has already submitted DKG R1Data")
//  }

  def validateDKGTransaction(tx: SignedTreasuryTransaction): Try[Unit] = Try {

    val range = tx match {
      case _: DKGr1Transaction => TreasuryManager.DISTR_KEY_GEN_R1_RANGE
      case _: DKGr2Transaction => TreasuryManager.DISTR_KEY_GEN_R2_RANGE
      case _: DKGr3Transaction => TreasuryManager.DISTR_KEY_GEN_R3_RANGE
      case _: DKGr4Transaction => TreasuryManager.DISTR_KEY_GEN_R4_RANGE
      case _: DKGr5Transaction => TreasuryManager.DISTR_KEY_GEN_R5_RANGE
    }

    val roundDataFromTrsryState = tx match {
      case _: DKGr1Transaction => trState.getDKGr1Data
      case _: DKGr2Transaction => trState.getDKGr2Data
      case _: DKGr3Transaction => trState.getDKGr3Data
      case _: DKGr4Transaction => trState.getDKGr4Data
      case _: DKGr5Transaction => trState.getDKGr5Data
    }

    val roundNumber = tx match {
      case _: DKGr1Transaction => 1
      case _: DKGr2Transaction => 2
      case _: DKGr3Transaction => 3
      case _: DKGr4Transaction => 4
      case _: DKGr5Transaction => 5
    }

    require(range.contains(epochHeight), s"Wrong height for DKG R$roundNumber transaction")

    val id = trState.getCommitteeSigningKeys.indexOf(tx.pubKey)
    require(id >= 0, "Committee member isn't found")
    require(!roundDataFromTrsryState.contains(id), s"The committee member has already submitted DKG R${roundNumber}Data")
  }
}
