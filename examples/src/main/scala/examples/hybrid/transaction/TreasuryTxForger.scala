package examples.hybrid.transaction

import akka.actor.{Actor, ActorRef}
import examples.commons.TreasuryMemPool
import examples.hybrid.HybridNodeViewHolder.{CurrentViewWithTreasuryState, GetDataFromCurrentViewWithTreasuryState}
import examples.hybrid.TreasuryManager
import examples.hybrid.history.HybridHistory
import examples.hybrid.settings.TreasurySettings
import examples.hybrid.state.HBoxStoredState
import examples.hybrid.transaction.BallotTransaction.VoterType
import examples.hybrid.transaction.RegisterTransaction.Role
import examples.hybrid.transaction.RegisterTransaction.Role.Role
import examples.hybrid.wallet.HWallet
import scorex.core.LocalInterface.LocallyGeneratedTransaction
import scorex.core.transaction.box.proposition.PublicKey25519Proposition
import scorex.core.utils.ScorexLogging
import treasury.crypto.core.{One, VoteCases}
import treasury.crypto.voting.RegularVoter
import treasury.crypto.voting.ballots.Ballot


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
    TreasuryMemPool,
    GeneratorInfo] = {
    val f: CurrentViewWithTreasuryState[HybridHistory, HBoxStoredState, HWallet, TreasuryMemPool] => GeneratorInfo = {
      view: CurrentViewWithTreasuryState[HybridHistory, HBoxStoredState, HWallet, TreasuryMemPool] =>
        GeneratorInfo(generate(view))
    }
    GetDataFromCurrentViewWithTreasuryState[HybridHistory,
      HBoxStoredState,
      HWallet,
      TreasuryMemPool,
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

  private def generateRegisterTx(view: NodeView): Seq[RegisterTransaction] = {
    def generateRegisterTx(role: Role, view: NodeView): Option[RegisterTransaction] = {
      val myStoredKeys = view.vault.treasurySecrets(role, view.trState.epochNum).map(_.pubKey)
      val myAlreadyRegistredKeys = view.trState.getKeys(role).filter(k => myStoredKeys.contains(k))
      val myPendingRegistrationKeys = view.pool.unconfirmed.map(_._2).filter {
        case tx: RegisterTransaction => tx.role == role && myStoredKeys.contains(tx.pubKey)
        case _ => false
      }

      if (myAlreadyRegistredKeys.isEmpty && myPendingRegistrationKeys.isEmpty)
        RegisterTransaction.create(view.vault, role, view.trState.epochNum).map(Some(_)).getOrElse(None)
      else None
    }

    var txs = List[RegisterTransaction]()
    if (settings.isCommittee)
      txs = txs ::: generateRegisterTx(Role.Committee, view).map(List(_)).getOrElse(List())
    if (settings.isExpert)
      txs = txs ::: generateRegisterTx(Role.Expert, view).map(List(_)).getOrElse(List())
    if (settings.isVoter)
      txs = txs ::: generateRegisterTx(Role.Voter, view).map(List(_)).getOrElse(List())
    txs
  }

  private def generateBallotTx(view: NodeView): Seq[BallotTransaction] = {
    val myStoredKeys = view.vault.treasurySecrets(Role.Voter, view.trState.epochNum)
    if (myStoredKeys.nonEmpty && view.trState.getSharedPubKey.isDefined) {
      val numberOfExperts = view.trState.getExpertsPubKeys.size
      val voter = new RegularVoter(TreasuryManager.cs, numberOfExperts, view.trState.getSharedPubKey.get, One)
      var ballots = List[Ballot]()
      for (i <- view.trState.getProposals.indices)
        ballots = voter.produceVote(i, VoteCases.Abstain) :: ballots

      Seq(BallotTransaction.create(myStoredKeys.head.pubKey, VoterType.Voter, ballots, view.trState.epochNum).get)
    } else Seq()
  }
}

object TreasuryTxForger {

  type NodeView = CurrentViewWithTreasuryState[HybridHistory, HBoxStoredState, HWallet, TreasuryMemPool]

  case class GeneratorInfo(txs: Seq[TreasuryTransaction])

  case object SuccessfullStateModification
}