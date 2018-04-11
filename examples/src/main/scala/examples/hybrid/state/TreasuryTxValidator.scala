package examples.hybrid.state

import java.math.BigInteger

import examples.commons.{SimpleBoxTransaction, SimpleBoxTx}
import examples.hybrid.TreasuryManager
import examples.hybrid.TreasuryManager.Role
import examples.hybrid.history.HybridHistory
import examples.hybrid.transaction.BallotTransaction.VoterType
import examples.hybrid.transaction.DKG._
import examples.hybrid.transaction.DecryptionShareTransaction.DecryptionRound
import examples.hybrid.transaction.RecoveryShareTransaction.RecoveryRound
import examples.hybrid.transaction._
import scorex.core.utils.ScorexLogging
import treasury.crypto.core.{PubKey, SimpleIdentifier}
import treasury.crypto.decryption.{DecryptionManager, RandomnessGenManager}
import treasury.crypto.keygen.DistrKeyGen
import treasury.crypto.keygen.datastructures.round3.R3Data
import treasury.crypto.voting.ballots.{ExpertBallot, VoterBallot}
import treasury.crypto.voting.{Expert, RegularVoter, Voter}

import scala.util.{Success, Try}

/**
  * Validates treasury transactions against current node view. Note that it is critical to pass consistent
  * TreasuryState, HybridHistory and HBoxStoredState. Inconsistent version of TreasuryState and HBoxStoredState (which
  * actually may happens during TreasuryState regeneration) will lead to failures during the PaymentTransaction verification.
  * Thus HybridHistory and HBoxStoredState are optional arguments and could be skipped. In this case deposits paybacks in
  * PaymentTransaction will not be verified, as well as RandomnessDecryption, but it should be suitable in some cases (for instance, during TreasuryState
  * regeneration, but not updating)
  *
  * @param trState TreasuryState
  * @param history History
  * @param state HBoxStoredState consistent to the trState (namely having the same version)
  * @param height height
  */
class TreasuryTxValidator(val trState: TreasuryState,
                          val height: Long,
                          val history: Option[HybridHistory] = None,
                          val state: Option[HBoxStoredState] = None) extends ScorexLogging {

  //  val epochHeight = height - (trState.epochNum * TreasuryManager.EPOCH_LEN)
  //  require(epochHeight >= 0 && epochHeight < TreasuryManager.EPOCH_LEN)
  // TODO: epochHeight and trState height may be inconsistent, consider this situation. At least it will happen for each first block in the epoch
  val epochHeight = height % TreasuryManager.EPOCH_LEN

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
      case t: ProposalTransaction => validateProposal(t).get
      case t: BallotTransaction => validateBallot(t).get
      case t: DecryptionShareTransaction => validateDecryptionShare(t).get
      case t: RecoveryShareTransaction => t.round match {
        case RecoveryRound.Randomness => validateRandomnessRecoveryTransaction(t).get
        case RecoveryRound.DecryptionR1 => validateDecryptionRecoveryShare(t).get
        case RecoveryRound.DecryptionR2 => validateDecryptionRecoveryShare(t).get
      }
      case t: DKGr1Transaction => validateDKGTransaction(t).get
      case t: DKGr2Transaction => validateDKGTransaction(t).get
      case t: DKGr3Transaction => validateDKGTransaction(t).get
      case t: DKGr4Transaction => validateDKGTransaction(t).get
      case t: DKGr5Transaction => validateDKGTransaction(t).get
      case t: RandomnessTransaction => validateRandomnessTransaction(t).get
      case t: RandomnessDecryptionTransaction => validateRandomnessDecryptionTransaction(t).get
      case t: PaymentTransaction => validatePayment(t).get
      case t: PenaltyTransaction => validatePenalty(t).get
    }
  }

  def validateRegistration(tx: RegisterTransaction): Try[Unit] = Try {
    val deposit = tx.to.filter(_._1 == TreasuryManager.VOTER_DEPOSIT_ADDR)
    require(deposit.size == 1, "Deposit should be as a single box payment")
    val depositAmount = deposit.headOption.get._2

    tx.role match {
      case Role.Expert =>
        require(TreasuryManager.EXPERT_REGISTER_RANGE.contains(epochHeight), "Wrong height for register transaction")
        require(!trState.getExpertsInfo.exists(_.signingKey == tx.pubKey), "Expert pubkey has been already registered")
        require(TreasuryManager.EXPERT_DEPOSIT_RANGE.contains(depositAmount), "Insufficient deposit")
      case Role.Voter =>
        require(TreasuryManager.VOTER_REGISTER_RANGE.contains(epochHeight), "Wrong height for register transaction")
        require(!trState.getVotersInfo.exists(_.signingKey == tx.pubKey), "Voter pubkey has been already registered")
        require(TreasuryManager.VOTER_DEPOSIT_RANGE.contains(depositAmount), "Insufficient deposit")
    }

    if (tx.committeeProxyPubKey.isDefined) {
      require(!trState.getCommitteeInfo.exists(_.signingKey == tx.pubKey), "Committee signing pubkey has been already registered")
      require(!trState.getCommitteeInfo.exists(_.proxyKey == tx.committeeProxyPubKey.get), "Committee proxy pubkey has been already registered")

      val committeeDeposit = tx.to.filter(_._1 == TreasuryManager.COMMITTEE_DEPOSIT_ADDR)
      require(committeeDeposit.size == 1, "Committee deposit should be as a single box payment")
      require(TreasuryManager.COMMITTEE_DEPOSIT_RANGE.contains(committeeDeposit.headOption.get._2), "Insufficient deposit amount")
    }
  }

  def validateProposal(tx: ProposalTransaction): Try[Unit] = Try {
    require(TreasuryManager.PROPOSAL_SUBMISSION_RANGE.contains(epochHeight), "Wrong height for proposal transaction")
    // TODO: add validation
    require(!trState.getProposals.exists(_.name == tx.name), "The proposal is already submitted")
  }

  def validateBallot(tx: BallotTransaction): Try[Unit] = Try {
    require(TreasuryManager.VOTING_RANGE.contains(epochHeight), "Wrong height for ballot transaction")
    require(trState.getSharedPubKey.isDefined, "Shared key is not defined in TreasuryState")
    require(trState.getProposals.nonEmpty, "Proposals are not defined")

    tx.voterType match {
      case VoterType.Voter =>
        val id = trState.getVotersInfo.indexWhere(_.signingKey == tx.pubKey)
        require(id >= 0, "Voter is not registered")
        require(!trState.getVotersBallots.contains(id), "The voter has already voted")
        tx.ballots.foreach(b => require(b.isInstanceOf[VoterBallot], "Incompatible ballot"))
        val expertsNum = trState.getExpertsInfo.size
        val stake = BigInteger.valueOf(trState.getVotersInfo(id).depositBox.value)
        val voter = new RegularVoter(TreasuryManager.cs, expertsNum, trState.getSharedPubKey.get, stake)
        tx.ballots.foreach { case b: VoterBallot =>
          require(b.uvChoice.length == Voter.VOTER_CHOISES_NUM)
          require(b.uvDelegations.length == expertsNum)
          require(b.stake.equals(stake))
          require(voter.verifyBallot(b), "Ballot NIZK is not verified")
        }

      case VoterType.Expert =>
        val id = trState.getExpertsInfo.indexWhere(_.signingKey == tx.pubKey)
        require(id >= 0, "Expert is not registered")
        require(trState.getExpertsBallots.contains(id) == false, "The expert has already voted")
        tx.ballots.foreach(b => require(b.isInstanceOf[ExpertBallot], "Incompatible ballot"))
        val expert = new Expert(TreasuryManager.cs, id, trState.getSharedPubKey.get)
        tx.ballots.foreach { b =>
          require(b.unitVector.length == Voter.VOTER_CHOISES_NUM)
          require(b.asInstanceOf[ExpertBallot].expertId == id, "Wrong expertId in a ballot")
          require(expert.verifyBallot(b), "Ballot NIZK is not verified")
        }
    }

    require(trState.getProposals.size == tx.ballots.size, "Number of ballots isn't equal to the number of proposals")
    trState.getProposals.indices.foreach(i =>
      require(tx.ballots.find(p => p.proposalId == i).isDefined, s"No ballot for proposal ${i}"))
  }

  def validateDecryptionShare(tx: DecryptionShareTransaction): Try[Unit] = Try {
    require(trState.getSharedPubKey.isDefined, "Shared key is not defined in TreasuryState")
    require(trState.getProposals.nonEmpty, "Proposals are not defined")

    val id = trState.getApprovedCommitteeInfo.indexWhere(_.signingKey == tx.pubKey)
    require(id >= 0, "Committee member isn't registered")
    require(!trState.getAllDisqualifiedCommitteeInfo.exists(_.signingKey == tx.pubKey), "Committee member is disqualified")

    require(tx.c1Shares.size > 0, "Decryption shares are not found")
    require(trState.getProposals.size == tx.c1Shares.size, "Number of decryption shares isn't equal to the number of proposals")
    trState.getProposals.indices.foreach(i =>
      require(tx.c1Shares.find(s => s.proposalId == i).isDefined, s"No C1Share for proposal ${i}"))

    tx.round match {
      case DecryptionRound.R1 => validateDecryptionShareR1(tx).get
      case DecryptionRound.R2 => validateDecryptionShareR2(tx).get
    }
  }

  def getPubKeyInCurrentEpoch(memberId: Int): Try[PubKey] = Try {
    val r3Data = trState.getDKGr3Data.values.find(_.issuerID == memberId)
    require(r3Data.isDefined, "Committee member hasn't posted R3 data in current epoch")
    TreasuryManager.cs.decodePoint(r3Data.get.commitments.head)
  }

  def validateDecryptionShareR1(tx: DecryptionShareTransaction): Try[Unit] = Try {
    require(TreasuryManager.VOTING_DECRYPTION_R1_RANGE.contains(epochHeight), "Wrong height for decryption share R1 transaction")
    require(tx.round == DecryptionRound.R1, "Invalid decryption share R1: wrong round")

    val id = trState.getApprovedCommitteeInfo.indexWhere(_.signingKey == tx.pubKey)
    require(!trState.getDecryptionSharesR1.contains(id), "The committee member has already submitted decryption shares R1")
    require(trState.getVotersBallots.size > 0, "The voter's ballots are absent. Decryption R1 should be skipped in this case")

    val expertsNum = trState.getExpertsInfo.size
    tx.c1Shares.foreach { s =>
      require(s.decryptedC1.size == expertsNum, "Invalid decryption share R1: wrong number of decrypted c1 componenets")
      val validator = new DecryptionManager(TreasuryManager.cs, trState.getBallotsForProposal(s.proposalId))
      val issuerPubKey = getPubKeyInCurrentEpoch(id)
      require(issuerPubKey.isSuccess, s"Can't get public key for committee member: ${id}")
      require(validator.validateDelegationsC1(issuerPubKey.get, s).isSuccess, "Invalid decryption share R1: NIZK is not verified")
    }
  }

  def validateDecryptionShareR2(tx: DecryptionShareTransaction): Try[Unit] = Try {
    require(TreasuryManager.VOTING_DECRYPTION_R2_RANGE.contains(epochHeight), "Wrong height for decryption share R2 transaction")
    require(tx.round == DecryptionRound.R2, "Invalid decryption share R2: wrong round")
    require(trState.getDelegations.isDefined, "Delegations are not defined, decryption share R2 can't be validated")

    val id = trState.getApprovedCommitteeInfo.indexWhere(_.signingKey == tx.pubKey)
    require(!trState.getDecryptionSharesR2.contains(id), "The committee member has already submitted decryption shares R2")

    tx.c1Shares.foreach { s =>
      require(s.decryptedC1.size == Voter.VOTER_CHOISES_NUM, "Invalid decryption share R2: wrong number of decrypted c1 componenets")
      val validator = new DecryptionManager(TreasuryManager.cs, trState.getBallotsForProposal(s.proposalId))
      val issuerPubKey = getPubKeyInCurrentEpoch(id)
      require(issuerPubKey.isSuccess, s"Can't get public key for committee member: ${id}")
      require(validator.validateChoicesC1(issuerPubKey.get, s, trState.getDelegations.get(s.proposalId)).isSuccess,
        "Invalid decryption share R2: NIZK is not verified")
    }
  }

  def validateDecryptionRecoveryShare(tx: RecoveryShareTransaction): Try[Unit] = Try {
    require(trState.getSharedPubKey.isDefined, "Shared key is not defined in TreasuryState")
    require(trState.getProposals.nonEmpty, "Proposals are not defined")

    val id = trState.getApprovedCommitteeInfo.indexWhere(_.signingKey == tx.pubKey)
    require(id >= 0, "Committee member isn't registered")
    require(!trState.getAllDisqualifiedCommitteeInfo.exists(_.signingKey == tx.pubKey), "Committee member is disqualified")
    require(tx.openedShares.nonEmpty, "No opened shares detected")

    val submitterInfo = trState.getApprovedCommitteeInfo(id)
    val identifier = new SimpleIdentifier(trState.getApprovedCommitteeInfo.map(_.proxyKey))
    val ids = tx.openedShares.map(_.violatorId)
    require(ids.size == ids.distinct.size, "The transaction contains duplicated OpenedShares")

    tx.openedShares.foreach { s =>
      val violatorProxyKey = trState.getApprovedCommitteeInfo(s.violatorId).proxyKey
      val valid = DistrKeyGen.validateRecoveryKeyShare(
        TreasuryManager.cs,
        identifier,
        submitterInfo.proxyKey,
        violatorProxyKey,
        trState.getDKGr1Data.values.toSeq,
        s.openedShare).isSuccess
      require(valid, "Invalid OpenedShare R1")
    }

    tx.round match {
      case RecoveryRound.DecryptionR1 => validateRecoveryShareR1(tx).get
      case RecoveryRound.DecryptionR2 => validateRecoveryShareR2(tx).get
    }
  }

  def validateRecoveryShareR1(tx: RecoveryShareTransaction): Try[Unit] = Try {
    require(TreasuryManager.VOTING_DECRYPTION_R1_RECOVERY_RANGE.contains(epochHeight), "Wrong height for recovery share R1 transaction")
    require(tx.round == RecoveryRound.DecryptionR1, "Invalid decryption share R1: wrong round")

    val id = trState.getApprovedCommitteeInfo.indexWhere(_.signingKey == tx.pubKey)

    tx.openedShares.foreach { s =>
      val submittedSharesOpt = Try(trState.getKeyRecoverySharesR1(s.violatorId)).toOption
      submittedSharesOpt.foreach(ss => require(!ss.exists(_.receiverID == id), "The OpenedShare R1 has already been submitted"))

      val violatorProxyKey = trState.getApprovedCommitteeInfo(s.violatorId).proxyKey
      val validViolator = trState.getDisqualifiedAfterDecryptionR1CommitteeInfo.exists(_.proxyKey == violatorProxyKey)
      require(validViolator, "Invalid OpenedShare: the target is not disqualified in R1")
    }
  }

  def validateRecoveryShareR2(tx: RecoveryShareTransaction): Try[Unit] = Try {
    require(TreasuryManager.VOTING_DECRYPTION_R2_RECOVERY_RANGE.contains(epochHeight), "Wrong height for recovery share R2 transaction")
    require(tx.round == RecoveryRound.DecryptionR2, "Invalid decryption share R2: wrong round")

    val id = trState.getApprovedCommitteeInfo.indexWhere(_.signingKey == tx.pubKey)

    tx.openedShares.foreach { s =>
      val submittedSharesOpt = Try(trState.getKeyRecoverySharesR2(s.violatorId)).toOption
      submittedSharesOpt.foreach(ss => require(!ss.exists(_.receiverID == id), "The OpenedShare R2 has already been submitted"))

      val violatorProxyKey = trState.getApprovedCommitteeInfo(s.violatorId).proxyKey
      val validViolator = trState.getDisqualifiedAfterDecryptionR2CommitteeInfo.exists(_.proxyKey == violatorProxyKey)
      require(validViolator, "Invalid OpenedShare: the target is not disqualified in R2")
    }
  }

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

    val id = trState.getApprovedCommitteeInfo.indexWhere(_.signingKey == tx.pubKey)
    require(id >= 0, "Committee member isn't found")
    require(!roundDataFromTrsryState.contains(id), s"The committee member has already submitted DKG R${roundNumber}Data")

    val committeeMembersPubKeys = trState.getApprovedCommitteeInfo.map(_.proxyKey)
    val memberIdentifier = new SimpleIdentifier(committeeMembersPubKeys)

    tx match {
      case t: DKGr1Transaction =>
        require(
          DistrKeyGen.checkR1Data(
            t.r1Data,
            memberIdentifier,
            committeeMembersPubKeys).isSuccess,
          s"Incorrect R1 data from member ${t.r1Data.issuerID}"
        )
      case t: DKGr2Transaction =>
        require(
          DistrKeyGen.checkR2Data(
            t.r2Data,
            memberIdentifier,
            committeeMembersPubKeys,
            trState.cs,
            trState.crs_h,
            trState.getDKGr1Data.values.toSeq).isSuccess,
          s"Incorrect R2 data from member ${t.r2Data.issuerID}"
        )
      case t: DKGr3Transaction =>
        require(
          DistrKeyGen.checkR3Data(
            t.r3Data,
            memberIdentifier,
            committeeMembersPubKeys,
            trState.cs,
            trState.getDKGr1Data.values.toSeq,
            trState.getDKGr2Data.values.toSeq).isSuccess,
          s"Incorrect R3 data from member ${t.r3Data.issuerID}"
        )
      case t: DKGr4Transaction =>
        require(
          DistrKeyGen.checkR4Data(
            t.r4Data,
            memberIdentifier,
            committeeMembersPubKeys,
            trState.cs,
            trState.crs_h,
            trState.getDKGr1Data.values.toSeq,
            trState.getDKGr2Data.values.toSeq,
            trState.getDKGr3Data.values.toSeq).isSuccess,
          s"Incorrect R4 data from member ${t.r4Data.issuerID}"
        )
      case t: DKGr5Transaction =>
        require(
          DistrKeyGen.checkR5Data(
            t.r5_1Data,
            memberIdentifier,
            committeeMembersPubKeys,
            trState.cs,
            trState.getDKGr1Data.values.toSeq,
            trState.getDKGr2Data.values.toSeq,
            trState.getDKGr3Data.values.toSeq,
            trState.getDKGr4Data.values.toSeq).isSuccess,
          s"Incorrect R5 data from member ${t.r5_1Data.issuerID}"
        )
    }
  }

  def validateRandomnessTransaction(tx: RandomnessTransaction): Try[Unit] = Try {
    require(TreasuryManager.RANDOMNESS_SUBMISSION_RANGE.contains(epochHeight), "Wrong height for randomness transaction")

    val id = trState.getApprovedCommitteeInfo.indexWhere(_.signingKey == tx.pubKey)
    require(id >= 0, "Committee member isn't registered")
    require(!trState.getAllDisqualifiedCommitteeInfo.exists(_.signingKey == tx.pubKey), "Committee member is disqualified")
    require(!trState.getSubmittedRandomnessForNextEpoch.contains(id), "The committee member has already submitted seed tx")
  }

  def validateRandomnessDecryptionTransaction(tx: RandomnessDecryptionTransaction): Try[Unit] = Try {
    require(TreasuryManager.RANDOMNESS_DECRYPTION_RANGE.contains(epochHeight), "Wrong height for randomness decryption transaction")
    require(trState.epochNum > 0, "Randomness decryption should not happen in the zero epoch")

    if (history.isDefined) {
      val prevEpochId = trState.epochNum - 1
      val prevCommittee = TreasuryState.generatePartiesInfo(history.get, prevEpochId).get._3.filter(_.approved)
      val prevRandomnessSumbmission = TreasuryState.generateRandomnessSubmission(history.get, prevEpochId).get

      val issuerInfo = prevCommittee.find(_.signingKey == tx.pubKey)
      require(issuerInfo.isDefined, "Committee member isn't registered")
      require(!trState.getDecryptedRandomness.contains(tx.pubKey), "The committee member has already submitted randomness decryption tx")

      val encryptedRandomness = prevRandomnessSumbmission.find(_._1 == issuerInfo.get.signingKey)
      require(encryptedRandomness.isDefined, "The committee member hasn't submitted RandomnessTransaction in the previoius epoch")

      val prevR3Data = TreasuryState.generateR3Data(history.get, prevEpochId).get
      val memberId = prevCommittee.indexWhere(_.signingKey == tx.pubKey)
      val issuerR3Data = prevR3Data.find(_.issuerID == memberId)
      require(issuerR3Data.isDefined, "Committee member hasn't posted R3 data in previous epoch")

      val issuerPubKey = TreasuryManager.cs.decodePoint(issuerR3Data.get.commitments.head)

      val valid = RandomnessGenManager.validateDecryptedRandomnessShare(
        TreasuryManager.cs, issuerPubKey, encryptedRandomness.get._2, tx.decryptedRandomness)
      require(valid, "Randomness decryption share is invalid")
    }
  }

  def validateRandomnessRecoveryTransaction(tx: RecoveryShareTransaction): Try[Unit] = Try {
    require(TreasuryManager.RANDOMNESS_DECRYPTION_RECOVERY_RANGE.contains(epochHeight), "Wrong height for recovery share Rand transaction")
    require(tx.round == RecoveryRound.Randomness, "Invalid decryption share rand: wrong round")

    if (history.isDefined) {
      val prevEpochId = trState.epochNum - 1
      val prevCommittee = TreasuryState.generatePartiesInfo(history.get, prevEpochId).get._3.filter(_.approved)
      val prevR1Data = TreasuryState.generateR1Data(history.get, prevEpochId).get

      val id = prevCommittee.indexWhere(_.signingKey == tx.pubKey)
      require(id >= 0, "Committee member isn't registered")
      require(tx.openedShares.nonEmpty, "No opened shares detected")

      val submitterInfo = prevCommittee(id)
      val identifier = new SimpleIdentifier(prevCommittee.map(_.proxyKey))
      val ids = tx.openedShares.map(_.violatorId)
      require(ids.size == ids.distinct.size, "The transaction contains duplicated OpenedShares")

      tx.openedShares.foreach { s =>
        val submittedSharesOpt = Try(trState.getKeyRecoverySharesRandGen(s.violatorId)).toOption
        submittedSharesOpt.foreach(ss => require(!ss.exists(_.receiverID == id), "The OpenedShare for Randomness has already been submitted"))

        val violatorProxyKey = prevCommittee(s.violatorId).proxyKey
        val validViolator = trState.getDisqualifiedAfterRandGenCommitteeInfo.exists(_.proxyKey == violatorProxyKey)
        require(validViolator, "Invalid OpenedShare: the target is not disqualified in RandGen")

        val valid = DistrKeyGen.validateRecoveryKeyShare(
          TreasuryManager.cs,
          identifier,
          submitterInfo.proxyKey,
          violatorProxyKey,
          prevR1Data,
          s.openedShare).isSuccess
        require(valid, "Invalid OpenedShare RandGen")
      }
    }
  }

  def validatePayment(tx: PaymentTransaction): Try[Unit] = Try {
    require(TreasuryManager.PAYMENT_BLOCK_HEIGHT == epochHeight, "Wrong height for payment transaction")

    val coinbasePayments = trState.getPayments.getOrElse(Seq())
    require(coinbasePayments.equals(tx.coinbasePayments), "Coinbase payments are invalid")

    if (history.isDefined && state.isDefined) {
      log.info("Validating deposit paybacks ...")
      val depositPaybacks = trState.getDepositPaybacks(history.get, state.get).getOrElse(Seq())
      require(depositPaybacks.equals(tx.depositPayback), "Deposit paybacks are invalid")
    }
  }

  def validatePenalty(tx: PenaltyTransaction): Try[Unit] = Try {
    require(TreasuryManager.PENALTY_BLOCK_HEIGHT == epochHeight, "Wrong height for penalty transaction")

    val penalties = trState.getPenalties
    require(penalties.equals(tx.depositsToDestroy), "Penalties are invalid")
  }
}

