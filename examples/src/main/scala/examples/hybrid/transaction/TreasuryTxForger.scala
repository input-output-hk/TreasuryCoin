package examples.hybrid.transaction

import akka.actor.{Actor, ActorRef, ActorSystem, Props}
import examples.commons.{SimpleBoxTransactionMemPool, Value}
import examples.hybrid.HybridNodeViewHolder.{CurrentViewWithTreasuryState, GetDataFromCurrentViewWithTreasuryState}
import examples.hybrid.TreasuryManager
import examples.hybrid.TreasuryManager.Role
import examples.hybrid.TreasuryManager.Role.Role
import examples.hybrid.history.HybridHistory
import examples.hybrid.mining.PosForger
import examples.hybrid.settings.{HybridSettings, TreasurySettings}
import examples.hybrid.state.{HBoxStoredState, TreasuryTxValidator}
import examples.hybrid.transaction.BallotTransaction.VoterType
import examples.hybrid.transaction.DecryptionShareTransaction.DecryptionRound
import examples.hybrid.transaction.DecryptionShareTransaction.DecryptionRound.DecryptionRound
import examples.hybrid.wallet.HWallet
import scorex.core.LocallyGeneratedModifiersMessages.ReceivableMessages.LocallyGeneratedTransaction
import scorex.core.transaction.box.proposition.PublicKey25519Proposition
import scorex.core.utils.ScorexLogging
import treasury.crypto.core.{One, VoteCases}
import treasury.crypto.keygen.DecryptionManager
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

    case SuccessfullStateModification =>
      viewHolderRef ! getRequiredData
  }

  private def generate(view: NodeView): Seq[TreasuryTransaction] = {
    import examples.hybrid.TreasuryManager._
    val epochHeight = view.history.height % TreasuryManager.EPOCH_LEN

    epochHeight match {
      case h if VOTER_REGISTER_RANGE.contains(h) => generateRegisterTx(Role.Voter, view)
      case h if EXPERT_REGISTER_RANGE.contains(h) => generateRegisterTx(Role.Expert, view)
      case h if COMMITTEE_REGISTER_RANGE.contains(h) => generateRegisterTx(Role.Committee, view)
      case h if DISTR_KEY_GEN_RANGE.contains(h) => Seq() // generateDKGTx(view)
      case h if VOTING_RANGE.contains(h) => generateBallotTx(view) // Only for testing! Normally a ballot should be created manually by a voter
      case h if VOTING_DECRYPTION_R1_RANGE.contains(h) => generateC1ShareR1(view)
      case h if VOTING_DECRYPTION_R2_RANGE.contains(h) => generateC1ShareR2(view)
      // TODO: other stages
      case _ => Seq()
    }
  }

  private def generateRegisterTx(role: Role, view: NodeView): Seq[TreasuryTransaction] = {
    // TODO: consider a better way to check if a node has already been registered for the role
    val tx = role match {
      case Role.Expert =>
        val isRegisteredAsExpert = view.vault.treasurySigningPubKeys(Role.Expert, view.trState.epochNum).nonEmpty
        if (settings.isExpert && !isRegisteredAsExpert)
          RegisterTransaction.create(view.vault, Role.Expert,
            Value @@ TreasuryManager.EXPERT_DEPOSIT_RANGE.start.toLong, 1, view.trState.epochNum).toOption
        else None
      case Role.Voter =>
        val isRegisteredAsVoter = view.vault.treasurySigningPubKeys(Role.Voter, view.trState.epochNum).nonEmpty
        if (settings.isVoter && !isRegisteredAsVoter)
          RegisterTransaction.create(view.vault, Role.Voter,
            Value @@ TreasuryManager.VOTER_DEPOSIT_RANGE.start.toLong, 1, view.trState.epochNum).toOption
        else None
      case Role.Committee =>
        val isRegisteredAsCommittee = view.vault.treasurySigningPubKeys(Role.Committee, view.trState.epochNum).nonEmpty
        if (settings.isCommittee && !isRegisteredAsCommittee)
          CommitteeRegisterTransaction.create(view.vault,
            Value @@ TreasuryManager.COMMITTEE_DEPOSIT_RANGE.start.toLong, 1, view.trState.epochNum).toOption
        else None
    }

    tx.map(Seq(_)).getOrElse(Seq())
  }

  /* It is only for testing purposes. Normally Ballot transactions should be created manually by a voter */
  private def generateBallotTx(view: NodeView): Seq[BallotTransaction] = {
    val myVoterKeys = view.vault.treasurySigningPubKeys(Role.Voter, view.trState.epochNum)
    val voterBallot = if (myVoterKeys.nonEmpty &&
        view.trState.getSharedPubKey.isDefined &&
        view.trState.getVotersSigningKeys.contains(myVoterKeys.head)) {
      val numberOfExperts = view.trState.getExpertsSigningKeys.size
      val voter = new RegularVoter(TreasuryManager.cs, numberOfExperts, view.trState.getSharedPubKey.get, One)
      var ballots = List[Ballot]()
      for (i <- view.trState.getProposals.indices)
        ballots = voter.produceDelegatedVote(i, 0) :: ballots

      val privKey = view.vault.treasurySigningSecretByPubKey(view.trState.epochNum, myVoterKeys.head).get.privKey
      Seq(BallotTransaction.create(privKey, VoterType.Voter, ballots, view.trState.epochNum).get)
    } else Seq()

    val myExpertKeys = view.vault.treasurySigningPubKeys(Role.Expert, view.trState.epochNum)
    val expertBallot = if (myExpertKeys.nonEmpty &&
        view.trState.getSharedPubKey.isDefined &&
        view.trState.getExpertsSigningKeys.contains(myExpertKeys.head)) {
      val expertId = view.trState.getExpertsSigningKeys.indexOf(myExpertKeys.head)
      val expert = new Expert(TreasuryManager.cs, expertId, view.trState.getSharedPubKey.get)
      var ballots = List[Ballot]()
      for (i <- view.trState.getProposals.indices)
        ballots = expert.produceVote(i, VoteCases.Yes) :: ballots

      val privKey = view.vault.treasurySigningSecretByPubKey(view.trState.epochNum, myExpertKeys.head).get.privKey
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

  private def generateC1ShareR1(view: NodeView): Seq[DecryptionShareTransaction] = {
    val myCommitteMemberSigningKey = view.vault.treasurySigningSecrets(Role.Committee, view.trState.epochNum).headOption
    val myCommitteMemberProxyKey = view.vault.treasuryCommitteeSecrets(view.trState.epochNum).headOption
    (myCommitteMemberSigningKey, myCommitteMemberProxyKey) match {
      case (Some(signingSecret), Some(committeeSecret)) =>
        val id = view.trState.getCommitteeSigningKeys.indexOf(signingSecret.privKey.publicImage)
        if (id >= 0) {
          val pending = view.pool.unconfirmed.map(_._2).find {
            case t: DecryptionShareTransaction => (t.round == DecryptionRound.R1) && (signingSecret.privKey.publicImage == t.pubKey)
            case _ => false
          }.isDefined
          val submitted = view.trState.getDecryptionSharesR1.find(_._1 == id).isDefined
          if (!pending && !submitted) {
            val c1Shares = view.trState.getProposals.indices.map { i =>
              val ballots = view.trState.getExpertBallotsForProposal(i) ++ view.trState.getVoterBallotsForProposal(i)
              val manager = new DecryptionManager(TreasuryManager.cs, ballots)
              manager.decryptC1ForDelegations(id, i, committeeSecret.privKey)
            }

            Seq(DecryptionShareTransaction.create(signingSecret.privKey, DecryptionRound.R1, c1Shares, view.trState.epochNum).get)
          } else Seq()
        } else Seq()
      case _ => Seq()
    }
  }

  private def generateC1ShareR2(view: NodeView): Seq[DecryptionShareTransaction] = {
    val myCommitteMemberSigningKey = view.vault.treasurySigningSecrets(Role.Committee, view.trState.epochNum).headOption
    val myCommitteMemberProxyKey = view.vault.treasuryCommitteeSecrets(view.trState.epochNum).headOption
    (myCommitteMemberSigningKey, myCommitteMemberProxyKey) match {
      case (Some(signingSecret), Some(committeeSecret)) =>
        val id = view.trState.getCommitteeSigningKeys.indexOf(signingSecret.privKey.publicImage)
        if (id >= 0) {
          val pending = view.pool.unconfirmed.map(_._2).find {
            case t: DecryptionShareTransaction => (t.round == DecryptionRound.R2) && (signingSecret.privKey.publicImage == t.pubKey)
            case _ => false
          }.isDefined
          val submitted = view.trState.getDecryptionSharesR2.find(_._1 == id).isDefined
          if (!pending && !submitted && view.trState.getDelegations.isDefined) {
            val c1Shares = view.trState.getProposals.indices.map { i =>
              val ballots = view.trState.getExpertBallotsForProposal(i) ++ view.trState.getVoterBallotsForProposal(i)
              val manager = new DecryptionManager(TreasuryManager.cs, ballots)
              manager.decryptC1ForChoices(id, i, committeeSecret.privKey, view.trState.getDelegations.get(i))
            }

            Seq(DecryptionShareTransaction.create(signingSecret.privKey, DecryptionRound.R2, c1Shares, view.trState.epochNum).get)
          } else Seq()
        } else Seq()
      case _ => Seq()
    }
  }
}

object TreasuryTxForger {

  type NodeView = CurrentViewWithTreasuryState[HybridHistory, HBoxStoredState, HWallet, SimpleBoxTransactionMemPool]

  case class GeneratorInfo(txs: Seq[TreasuryTransaction])

  case object SuccessfullStateModification
}

object TreasuryTxForgerRef {

  def props(viewHolderRef: ActorRef, settings: TreasurySettings): Props = Props(new TreasuryTxForger(viewHolderRef, settings))

  def apply(viewHolderRef: ActorRef, settings: TreasurySettings)
           (implicit system: ActorSystem): ActorRef = system.actorOf(props(viewHolderRef, settings))

  def apply(name: String, viewHolderRef: ActorRef, settings: TreasurySettings)
           (implicit system: ActorSystem): ActorRef = system.actorOf(props(viewHolderRef, settings), name)
}