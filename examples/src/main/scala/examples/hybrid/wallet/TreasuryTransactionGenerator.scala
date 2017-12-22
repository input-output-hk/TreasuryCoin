package examples.hybrid.wallet

import akka.actor.{Actor, ActorRef}
import examples.commons.TreasuryMemPool
import examples.hybrid.history.HybridHistory
import examples.hybrid.state.HBoxStoredState
import examples.hybrid.transaction.{CommitteeRegisterTx, TreasuryTransaction}
import scorex.core.LocalInterface.LocallyGeneratedTransaction
import scorex.core.NodeViewHolder.{CurrentView, GetDataFromCurrentView}
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

  private val getRequiredData: GetDataFromCurrentView[HybridHistory,
    HBoxStoredState,
    HWallet,
    TreasuryMemPool,
    GeneratorInfo] = {
    val f: CurrentView[HybridHistory, HBoxStoredState, HWallet, TreasuryMemPool] => GeneratorInfo = {
      view: CurrentView[HybridHistory, HBoxStoredState, HWallet, TreasuryMemPool] =>
        GeneratorInfo(generate(view.vault))
    }
    GetDataFromCurrentView[HybridHistory,
      HBoxStoredState,
      HWallet,
      TreasuryMemPool,
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

  def generate(wallet: HWallet): Try[TreasuryTransaction] = {
    CommitteeRegisterTx.create(wallet, 1L, (1L,10L)).flatMap(t => Try(t._1))
  }
}

object TreasuryTransactionGenerator {

  case class StartGeneration(delay: FiniteDuration)

  case class GeneratorInfo(tx: Try[TreasuryTransaction])

}

