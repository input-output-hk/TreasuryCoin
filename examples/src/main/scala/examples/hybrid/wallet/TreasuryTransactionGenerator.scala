package examples.hybrid.wallet

import akka.actor.{Actor, ActorRef}
import examples.commons.{SimpleBoxTransactionMemPool, Value}
import examples.hybrid.HybridNodeViewHolder.{CurrentViewWithTreasuryState, GetDataFromCurrentViewWithTreasuryState}
import examples.hybrid.history.HybridHistory
import examples.hybrid.state.{HBoxStoredState, TreasuryState}
import examples.hybrid.transaction.{ProposalTransaction, RegisterTransaction, TreasuryTransaction}
import scorex.core.LocalInterface.LocallyGeneratedTransaction
import scorex.core.transaction.box.proposition.PublicKey25519Proposition
import scorex.core.utils.ScorexLogging

import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.duration.FiniteDuration
import scala.util.{Failure, Success, Try}

/**
  * Generator of TreasuryTransaction
  */
class TreasuryTransactionGenerator(viewHolderRef: ActorRef) extends Actor with ScorexLogging {

  import TreasuryTransactionGenerator._

  private val getRequiredData: GetDataFromCurrentViewWithTreasuryState[HybridHistory,
    HBoxStoredState,
    HWallet,
    SimpleBoxTransactionMemPool,
    GeneratorInfo] = {
    val f: CurrentViewWithTreasuryState[HybridHistory, HBoxStoredState, HWallet, SimpleBoxTransactionMemPool] => GeneratorInfo = {
      view: CurrentViewWithTreasuryState[HybridHistory, HBoxStoredState, HWallet, SimpleBoxTransactionMemPool] =>
        GeneratorInfo(generate(view.vault, view.trState))
    }
    GetDataFromCurrentViewWithTreasuryState[HybridHistory,
      HBoxStoredState,
      HWallet,
      SimpleBoxTransactionMemPool,
      GeneratorInfo](f)
  }


  override def receive: Receive = {
    case StartGeneration(duration) =>
      context.system.scheduler.schedule(duration, duration, viewHolderRef, getRequiredData)

    //    case CurrentView(_, _, wallet: HWallet, _) =>
    case gi: GeneratorInfo =>
      gi.tx match {
        case Success(tx) =>
          log.info(s"Local tx with with ${tx.from.size} inputs, ${tx.to.size} outputs. Valid: ${tx.semanticValidity}")
          viewHolderRef ! LocallyGeneratedTransaction[PublicKey25519Proposition, TreasuryTransaction](tx)
        case Failure(e) =>
          e.printStackTrace()
      }
  }

  def generate(wallet: HWallet, trState: TreasuryState): Try[TreasuryTransaction] = {
    //RegisterTransaction.create(wallet, Role.Expert, trState.epochNum)

    val pubkey = wallet.publicKeys.toSeq.head
    ProposalTransaction.create(wallet, "TestProposal", Value @@ 10L, pubkey, trState.epochNum)
  }
}

object TreasuryTransactionGenerator {

  case class StartGeneration(delay: FiniteDuration)

  case class GeneratorInfo(tx: Try[TreasuryTransaction])

}

