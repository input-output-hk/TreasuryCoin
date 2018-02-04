package examples.hybrid.transaction

import akka.actor.{Actor, ActorRef}
import examples.commons.SimpleBoxTransactionMemPool
import examples.hybrid.HybridNodeViewHolder.{CurrentViewWithTreasuryState, GetDataFromCurrentViewWithTreasuryState}
import examples.hybrid.TreasuryManager
import examples.hybrid.TreasuryManager.Role
import examples.hybrid.TreasuryManager.Role.Role
import examples.hybrid.history.HybridHistory
import examples.hybrid.settings.TreasurySettings
import examples.hybrid.state.{HBoxStoredState, TreasuryTxValidator}
import examples.hybrid.transaction.BallotTransaction.VoterType
import examples.hybrid.wallet.HWallet
import scorex.core.LocalInterface.LocallyGeneratedTransaction
import scorex.core.transaction.box.proposition.PublicKey25519Proposition
import scorex.core.utils.ScorexLogging
import treasury.crypto.core.{One, VoteCases}
import treasury.crypto.voting.ballots.Ballot
import treasury.crypto.voting.{Expert, RegularVoter}


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

    view.history.height match {
      case h if REGISTER_RANGE.contains(h) => generateRegisterTx(view)
      case h if DISTR_KEY_GEN_RANGE.contains(h) => Seq() // generateDKGTx(view)
      case h if VOTING_RANGE.contains(h) => generateBallotTx(view) // Only for testing! Normally a ballot should be created manually by a voter
      // TODO: other stages
      case _ => Seq()
    }
  }

  private def generateRegisterTx(view: NodeView): Seq[TreasuryTransaction] = {
    // TODO: consider a better way to check if a node has already been registered for the role
    val isRegisteredAsCommittee = view.vault.treasurySigningPubKeys(Role.Committee, view.trState.epochNum).nonEmpty
    val isRegisteredAsExpert = view.vault.treasurySigningPubKeys(Role.Expert, view.trState.epochNum).nonEmpty
    val isRegisteredAsVoter = view.vault.treasurySigningPubKeys(Role.Voter, view.trState.epochNum).nonEmpty

    var txs = List[TreasuryTransaction]()
    if (settings.isCommittee && !isRegisteredAsCommittee)
      txs = CommitteeRegisterTransaction.create(view.vault, view.trState.epochNum).get :: txs
    if (settings.isExpert && !isRegisteredAsExpert)
      txs = RegisterTransaction.create(view.vault, Role.Expert, view.trState.epochNum).get :: txs
    if (settings.isVoter && !isRegisteredAsVoter)
      txs = RegisterTransaction.create(view.vault, Role.Voter, view.trState.epochNum).get :: txs
    txs
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
        ballots = voter.produceVote(i, VoteCases.Abstain) :: ballots

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
        ballots = expert.produceVote(i, VoteCases.Abstain) :: ballots

      val privKey = view.vault.treasurySigningSecretByPubKey(view.trState.epochNum, myExpertKeys.head).get.privKey
      Seq(BallotTransaction.create(privKey, VoterType.Expert, ballots, view.trState.epochNum).get)
    } else Seq()

    // check that txs are valid and haven't been submitted before
    (voterBallot ++ expertBallot).filter { tx =>
      val pending = view.pool.unconfirmed.map(_._2).find {
        case t: BallotTransaction => t.pubKey == tx.pubKey
        case _ => false
      }.isDefined
      val valid = new TreasuryTxValidator(view.trState, view.history.height).validate(tx).isSuccess
      !pending && valid
    }
  }
}

object TreasuryTxForger {

  type NodeView = CurrentViewWithTreasuryState[HybridHistory, HBoxStoredState, HWallet, SimpleBoxTransactionMemPool]

  case class GeneratorInfo(txs: Seq[TreasuryTransaction])

  case object SuccessfullStateModification
}