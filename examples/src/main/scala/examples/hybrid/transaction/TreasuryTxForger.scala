package examples.hybrid.transaction

import java.math.BigInteger

import akka.actor.{Actor, ActorRef, ActorSystem, Props}
import examples.commons.{SimpleBoxTransactionMemPool, Value}
import examples.hybrid.HybridNodeViewHolder.{CurrentViewWithTreasuryState, GetDataFromCurrentViewWithTreasuryState}
import examples.hybrid.TreasuryManager
import examples.hybrid.TreasuryManager.Role
import examples.hybrid.TreasuryManager.Role.Role
import examples.hybrid.history.HybridHistory
import examples.hybrid.settings.TreasurySettings
import examples.hybrid.state.{HBoxStoredState, TreasuryState, TreasuryTxValidator}
import examples.hybrid.transaction.BallotTransaction.VoterType
import examples.hybrid.transaction.DecryptionShareTransaction.DecryptionRound
import examples.hybrid.transaction.DecryptionShareTransaction.DecryptionRound.DecryptionRound
import examples.hybrid.transaction.RecoveryShareTransaction.RecoveryRound.RecoveryRound
import examples.hybrid.transaction.RecoveryShareTransaction.{OpenedShareWithId, RecoveryRound}
import examples.hybrid.wallet.{HWallet, TreasuryCommitteeSecret, TreasurySigningSecret}
import scorex.core.NodeViewHolder.ReceivableMessages.LocallyGeneratedTransaction
import scorex.core.transaction.box.proposition.PublicKey25519Proposition
import scorex.core.utils.ScorexLogging
import treasury.crypto.core.{SimpleIdentifier, VoteCases}
import treasury.crypto.decryption.{DecryptionManager, RandomnessGenManager}
import treasury.crypto.keygen.DistrKeyGen
import treasury.crypto.voting.ballots.Ballot
import treasury.crypto.voting.{Expert, RegularVoter}

import scala.util.Try


/**
  * It's an automatic bot that generates necessary transactions for maintaining treasury operation.
  * For example it will operate distributed key generation if a node is registered as committee member or
  * it will automatically generate a registration tx at the appropriate time if a node wants to be a committee.
  * To accomplish this goal the bot will subscribe to state update notifications and check if the current
  * node needs to perform some actions depending on the current state of the epoch.
  * The bot is intended to take control only of those transactions that don't require human decision.
  */
class TreasuryTxForger(viewHolderRef: ActorRef, settings: TreasurySettings) extends Actor with ScorexLogging {

  import TreasuryTxForger._

  private val getRequiredData: GetDataFromCurrentViewWithTreasuryState[HybridHistory,
    HBoxStoredState,
    HWallet,
    SimpleBoxTransactionMemPool,
    GeneratorInfo] = {
    val f: CurrentViewWithTreasuryState[HybridHistory, HBoxStoredState, HWallet, SimpleBoxTransactionMemPool] => GeneratorInfo = {
      view: CurrentViewWithTreasuryState[HybridHistory, HBoxStoredState, HWallet, SimpleBoxTransactionMemPool] =>
        GeneratorInfo(generate(view))
    }
    GetDataFromCurrentViewWithTreasuryState[HybridHistory,
      HBoxStoredState,
      HWallet,
      SimpleBoxTransactionMemPool,
      GeneratorInfo](f)
  }

  override def receive: Receive = {
    case gi: GeneratorInfo =>
      gi.txs.foreach { tx =>
        log.info(s"Locally generated automatic treasury tx ${tx.getClass.getName}")
        viewHolderRef ! LocallyGeneratedTransaction[PublicKey25519Proposition, TreasuryTransaction](tx)
      }

    case ForgeTreasuryTransactions =>
      viewHolderRef ! getRequiredData
  }

  private def generate(view: NodeView): Seq[TreasuryTransaction] = {
    import examples.hybrid.TreasuryManager._
    val epochHeight = view.history.height % TreasuryManager.EPOCH_LEN

    val txsTry: Try[Seq[TreasuryTransaction]] = epochHeight match {
      case h if VOTER_REGISTER_RANGE.contains(h) => generateRegisterTx(Role.Voter, view)
      case h if EXPERT_REGISTER_RANGE.contains(h) => generateRegisterTx(Role.Expert, view)
      case h if RANDOMNESS_DECRYPTION_RANGE.contains(h) => generateRandomnessDecryptionTx(view)
      case h if RANDOMNESS_DECRYPTION_RECOVERY_RANGE.contains(h) => generateRandomnessRecoveryShare(view)
      case h if VOTING_RANGE.contains(h) && settings.automaticBallotGeneration => generateBallotTx(view) // Only for testing! Normally a ballot should be created manually by a voter
      case h if VOTING_DECRYPTION_R1_RANGE.contains(h) => generateC1ShareR1(view)
      case h if VOTING_DECRYPTION_R1_RECOVERY_RANGE.contains(h) => generateRecoveryShare(RecoveryRound.DecryptionR1, view)
      case h if VOTING_DECRYPTION_R2_RANGE.contains(h) => generateC1ShareR2(view)
      case h if VOTING_DECRYPTION_R2_RECOVERY_RANGE.contains(h) => generateRecoveryShare(RecoveryRound.DecryptionR2, view)
      case h if RANDOMNESS_SUBMISSION_RANGE.contains(h) => generateRandomnessTx(view)
      case _ => Try(Seq())
    }

    txsTry.recoverWith { case e =>
      log.error("Can't create treasury tx: ", e)
      Try(Seq())
    }.get
  }

  private def generateRegisterTx(role: Role, view: NodeView): Try[Seq[TreasuryTransaction]] = Try {
    // TODO: consider a better way to check if a node has already been registered for the role
    val tx = role match {
      case Role.Expert =>
        val isRegisteredAsExpert = view.vault.treasurySigningPubKeys(Role.Expert, view.trState.epochNum).nonEmpty
        if (settings.isExpert && !isRegisteredAsExpert)
          RegisterTransaction.create(view.vault, Role.Expert,
            Value @@ TreasuryManager.EXPERT_DEPOSIT_RANGE.start.toLong, settings.isCommittee, 1, view.trState.epochNum).toOption
        else None
      case Role.Voter =>
        val isRegisteredAsVoter = view.vault.treasurySigningPubKeys(Role.Voter, view.trState.epochNum).nonEmpty
        if (settings.isVoter && !isRegisteredAsVoter)
          RegisterTransaction.create(view.vault, Role.Voter,
            Value @@ TreasuryManager.VOTER_DEPOSIT_RANGE.start.toLong, settings.isCommittee, 1, view.trState.epochNum).toOption
        else None
    }

    tx.map(Seq(_)).getOrElse(Seq())
  }

  /* It is only for testing purposes. Normally Ballot transactions should be created manually by a voter */
  private def generateBallotTx(view: NodeView): Try[Seq[BallotTransaction]] = Try {
    val myVoterKey = view.vault.treasurySigningPubKeys(Role.Voter, view.trState.epochNum).headOption
    val voterBallot = if (myVoterKey.isDefined &&
        view.trState.getSharedPubKey.isDefined &&
        view.trState.getVotersInfo.exists(_.signingKey == myVoterKey.get)) {
      val numberOfExperts = view.trState.getExpertsInfo.size
      val stake = view.trState.getVotersInfo.find(_.signingKey == myVoterKey.get).get.depositBox.value
      val voter = new RegularVoter(TreasuryManager.cs, numberOfExperts, view.trState.getSharedPubKey.get, BigInteger.valueOf(stake))
      var ballots = List[Ballot]()
      for (i <- view.trState.getProposals.indices) {
        if (numberOfExperts > 0)
          ballots = voter.produceDelegatedVote(i, 0) :: ballots
        else
          ballots = voter.produceVote(i, VoteCases.Yes) :: ballots
      }

      val privKey = view.vault.treasurySigningSecretByPubKey(view.trState.epochNum, myVoterKey.get).get.privKey
      Seq(BallotTransaction.create(privKey, VoterType.Voter, ballots, view.trState.epochNum).get)
    } else Seq()

    val myExpertKey = view.vault.treasurySigningPubKeys(Role.Expert, view.trState.epochNum).headOption
    val expertBallot = if (myExpertKey.isDefined &&
        view.trState.getSharedPubKey.isDefined &&
        view.trState.getExpertsInfo.exists(_.signingKey == myExpertKey.get)) {
      val expertId = view.trState.getExpertsInfo.indexWhere(_.signingKey == myExpertKey.get)
      val expert = new Expert(TreasuryManager.cs, expertId, view.trState.getSharedPubKey.get)
      var ballots = List[Ballot]()
      for (i <- view.trState.getProposals.indices)
        ballots = expert.produceVote(i, VoteCases.Yes) :: ballots

      val privKey = view.vault.treasurySigningSecretByPubKey(view.trState.epochNum, myExpertKey.get).get.privKey
      Seq(BallotTransaction.create(privKey, VoterType.Expert, ballots, view.trState.epochNum).get)
    } else Seq()

    // check that txs are valid and haven't been submitted before
    (voterBallot ++ expertBallot).filter { tx =>
      val pending = view.pool.unconfirmed.map(_._2).find {
        case t: BallotTransaction => t.pubKey == tx.pubKey
        case _ => false
      }.isDefined
      val valid = Try(new TreasuryTxValidator(view.trState, view.history.height)).flatMap(_.validate(tx)).isSuccess
      !pending && valid
    }
  }

  private def generateC1ShareR1(view: NodeView): Try[Seq[DecryptionShareTransaction]] = Try {
    val secrets = checkCommitteeMemberRegistration(view)
    if (secrets.isDefined) {
      val (signingSecret, proxySecret) = secrets.get
      val id = view.trState.getApprovedCommitteeInfo.indexWhere(
        c => c.signingKey == signingSecret.privKey.publicImage && c.proxyKey == proxySecret.pubKey)
      if (id >= 0) {
        val pending = view.pool.unconfirmed.map(_._2).find {
          case t: DecryptionShareTransaction => (t.round == DecryptionRound.R1) && (signingSecret.privKey.publicImage == t.pubKey)
          case _ => false
        }.isDefined
        if (!pending) {
          val c1Shares = view.trState.getProposals.indices.map { i =>
            val ballots = view.trState.getExpertBallotsForProposal(i) ++ view.trState.getVoterBallotsForProposal(i)
            val manager = new DecryptionManager(TreasuryManager.cs, ballots)
            manager.decryptC1ForDelegations(id, i, proxySecret.secretKey)
          }

          val tx = DecryptionShareTransaction.create(signingSecret.privKey, DecryptionRound.R1, c1Shares, view.trState.epochNum).get
          val valid = Try(new TreasuryTxValidator(view.trState, view.history.height + 1, Some(view.history))).flatMap(_.validate(tx))
          if(valid.isSuccess) Seq(tx) else Seq()
        } else Seq()
      } else Seq()
    } else Seq()
  }

  private def generateRecoveryShare(round: RecoveryRound, view: NodeView): Try[Seq[RecoveryShareTransaction]] = Try {
    val secrets = checkCommitteeMemberRegistration(view)
    if (secrets.isDefined) {
      val (signingSecret, proxySecret) = secrets.get

      val needRecover = round match {
        case RecoveryRound.DecryptionR1 => view.trState.getDisqualifiedAfterDecryptionR1CommitteeInfo
        case RecoveryRound.DecryptionR2 => view.trState.getDisqualifiedAfterDecryptionR2CommitteeInfo
      }
      val pending = view.pool.unconfirmed.map(_._2).find {
        case t: RecoveryShareTransaction => (t.round == round) && (signingSecret.privKey.publicImage == t.pubKey)
        case _ => false
      }.isDefined

      if (needRecover.nonEmpty && !pending) {
        val identifier = new SimpleIdentifier(view.trState.getApprovedCommitteeInfo.map(_.proxyKey))

        val shares = needRecover.map { violator =>
          val violatorId = view.trState.getApprovedCommitteeInfo.indexWhere(_.signingKey == violator.signingKey)
          val openedShare = DistrKeyGen.generateRecoveryKeyShare(
            TreasuryManager.cs,
            identifier,
            (proxySecret.privKey, proxySecret.pubKey),
            violator.proxyKey,
            view.trState.getDKGr1Data.values.toSeq).get
          OpenedShareWithId(violatorId, openedShare)
        }

        val tx = RecoveryShareTransaction.create(signingSecret.privKey, round, shares, view.trState.epochNum).get
        val valid = Try(new TreasuryTxValidator(view.trState, view.history.height + 1)).flatMap(_.validate(tx))
        if(valid.isSuccess) Seq(tx) else Seq()

      } else Seq()
    } else Seq()
  }

  private def generateC1ShareR2(view: NodeView): Try[Seq[DecryptionShareTransaction]] = Try {
    val secrets = checkCommitteeMemberRegistration(view)
    if (secrets.isDefined) {
      val (signingSecret, proxySecret) = secrets.get
      val id = view.trState.getApprovedCommitteeInfo.indexWhere(
        c => c.signingKey == signingSecret.privKey.publicImage && c.proxyKey == proxySecret.pubKey)
      if (id >= 0) {
        val pending = view.pool.unconfirmed.map(_._2).find {
          case t: DecryptionShareTransaction => (t.round == DecryptionRound.R2) && (signingSecret.privKey.publicImage == t.pubKey)
          case _ => false
        }.isDefined
        if (!pending && view.trState.getDelegations.isDefined) {
          val c1Shares = view.trState.getProposals.indices.map { i =>
            val ballots = view.trState.getExpertBallotsForProposal(i) ++ view.trState.getVoterBallotsForProposal(i)
            val manager = new DecryptionManager(TreasuryManager.cs, ballots)
            manager.decryptC1ForChoices(id, i, proxySecret.secretKey, view.trState.getDelegations.get(i))
          }

          val tx = DecryptionShareTransaction.create(signingSecret.privKey, DecryptionRound.R2, c1Shares, view.trState.epochNum).get
          val valid = Try(new TreasuryTxValidator(view.trState, view.history.height + 1, Some(view.history))).flatMap(_.validate(tx))
          if(valid.isSuccess) Seq(tx) else Seq()
        } else Seq()
      } else Seq()
    } else Seq()
  }

  private def generateRandomnessTx(view: NodeView): Try[Seq[RandomnessTransaction]] = Try {
    val secrets = checkCommitteeMemberRegistration(view)
    if (secrets.isDefined) {
      val (signingSecret, proxySecret) = secrets.get

      val pending = view.pool.unconfirmed.map(_._2).find {
        case t: RandomnessTransaction => signingSecret.privKey.publicImage == t.pubKey
        case _ => false
      }.isDefined

      if (!pending) {
        val seed = RandomnessGenManager.getRand(TreasuryManager.cs, proxySecret.secretKey.toByteArray)
        val pubKey = TreasuryManager.cs.basePoint.multiply(proxySecret.secretKey)
        val encryptedSeed = RandomnessGenManager.encryptRandomnessShare(TreasuryManager.cs, pubKey, seed)

        val tx = RandomnessTransaction.create(signingSecret.privKey, encryptedSeed, view.trState.epochNum).get
        val valid = Try(new TreasuryTxValidator(view.trState, view.history.height + 1, Some(view.history))).flatMap(_.validate(tx))
        if(valid.isSuccess) Seq(tx) else Seq()
      } else Seq()
    } else Seq()
  }

  /**
    * This transaction should be generated by a committe member from the previous epoch
    * @param view
    * @return
    */
  private def generateRandomnessDecryptionTx(view: NodeView): Try[Seq[RandomnessDecryptionTransaction]] = Try {
    val prevEpochId = view.trState.epochNum - 1
    val secrets = checkCommitteeMemberRegistration(view, Some(prevEpochId))
    if (prevEpochId >= 0 && secrets.isDefined) {
      val (signingSecret, proxySecret) = secrets.get

      val pending = view.pool.unconfirmed.map(_._2).find {
        case t: RandomnessDecryptionTransaction => signingSecret.privKey.publicImage == t.pubKey
        case _ => false
      }.isDefined

      if (!pending) {
        val mySigningPubKey = signingSecret.privKey.publicImage
        val randomnessSubmissionOpt = TreasuryState.generateRandomnessSubmission(view.history, prevEpochId).toOption
        val myEncryptedRandomness = randomnessSubmissionOpt.flatMap(_.find(_._1 == mySigningPubKey))
        if (myEncryptedRandomness.isDefined) {
          val decryptedRandomness = RandomnessGenManager.decryptRandomnessShare(
            TreasuryManager.cs, proxySecret.secretKey, myEncryptedRandomness.get._2)

          val tx = RandomnessDecryptionTransaction.create(signingSecret.privKey, decryptedRandomness, view.trState.epochNum).get
          val valid = Try(new TreasuryTxValidator(view.trState, view.history.height + 1, Some(view.history))).flatMap(_.validate(tx))
          if (valid.isSuccess) Seq(tx) else Seq()
        } else Seq()
      } else Seq()
    } else Seq()
  }

  /**
    * This transaction should be generated by a committe member from the previous epoch
    * @param view
    * @return
    */
  private def generateRandomnessRecoveryShare(view: NodeView): Try[Seq[RecoveryShareTransaction]] = Try {
    val prevEpochId = view.trState.epochNum - 1
    val secrets = checkCommitteeMemberRegistration(view, Some(prevEpochId))
    if (prevEpochId >= 0 && secrets.isDefined) {
      val (signingSecret, proxySecret) = secrets.get

      val disqualified = view.trState.getDisqualifiedAfterRandGenCommitteeInfo
      val pending = view.pool.unconfirmed.map(_._2).find {
        case t: RecoveryShareTransaction => (t.round == RecoveryRound.Randomness) && (signingSecret.privKey.publicImage == t.pubKey)
        case _ => false
      }.isDefined

      if (disqualified.nonEmpty && !pending) {
        val prevCommittee = TreasuryState.generatePartiesInfo(view.history, prevEpochId).get._3.filter(_.approved)
        val identifier = new SimpleIdentifier(prevCommittee.map(_.proxyKey))
        val prevR1Data = TreasuryState.generateR1Data(view.history, prevEpochId).get

        val shares = disqualified.map { violator =>
          val violatorId = prevCommittee.indexWhere(_.signingKey == violator.signingKey)
          val openedShare = DistrKeyGen.generateRecoveryKeyShare(
            TreasuryManager.cs,
            identifier,
            (proxySecret.privKey, proxySecret.pubKey),
            violator.proxyKey,
            prevR1Data).get
          OpenedShareWithId(violatorId, openedShare)
        }

        val tx = RecoveryShareTransaction.create(signingSecret.privKey, RecoveryRound.Randomness, shares, view.trState.epochNum).get
        val valid = Try(new TreasuryTxValidator(view.trState, view.history.height + 1, Some(view.history))).flatMap(_.validate(tx))
        if(valid.isSuccess) Seq(tx) else Seq()

      } else Seq()
    } else Seq()
  }

  /**
    *  Check if a current node is registered as a committee member in a particualar epoch
    *  @param view
    *  @param epochIdOpt if None, the current epoch will be checked
    */
  private def checkCommitteeMemberRegistration(view: NodeView, epochIdOpt: Option[Int] = None): Option[(TreasurySigningSecret, TreasuryCommitteeSecret)] = {
    val (epochId, committeeInfoOpt) =
      if (epochIdOpt.isDefined) {
        val committee = TreasuryState.generatePartiesInfo(view.history, epochIdOpt.get).map(_._3.filter(_.approved)).toOption
        (epochIdOpt.get, committee)
      } else {
        (view.trState.epochNum, Option(view.trState.getApprovedCommitteeInfo))
      }

    if (committeeInfoOpt.isDefined) {
      val myCommitteMemberSigningKey = view.vault.treasurySigningSecrets(epochId).headOption
      val myCommitteMemberProxyKey = view.vault.treasuryCommitteeSecrets(epochId).headOption
      (myCommitteMemberSigningKey, myCommitteMemberProxyKey) match {
        case (Some(signingSecret), Some(committeeSecret)) =>
          val id = committeeInfoOpt.get.indexWhere(
            c => c.signingKey == signingSecret.privKey.publicImage && c.proxyKey == committeeSecret.pubKey)
          if (id >= 0) {
            Some((signingSecret, committeeSecret))
          } else None
        case _ => None
      }
    } else None
  }
}

object TreasuryTxForger {

  type NodeView = CurrentViewWithTreasuryState[HybridHistory, HBoxStoredState, HWallet, SimpleBoxTransactionMemPool]

  case class GeneratorInfo(txs: Seq[TreasuryTransaction])

  case object ForgeTreasuryTransactions
}

object TreasuryTxForgerRef {

  def props(viewHolderRef: ActorRef, settings: TreasurySettings): Props = Props(new TreasuryTxForger(viewHolderRef, settings))

  def apply(viewHolderRef: ActorRef, settings: TreasurySettings)
           (implicit system: ActorSystem): ActorRef = system.actorOf(props(viewHolderRef, settings))

  def apply(name: String, viewHolderRef: ActorRef, settings: TreasurySettings)
           (implicit system: ActorSystem): ActorRef = system.actorOf(props(viewHolderRef, settings), name)
}