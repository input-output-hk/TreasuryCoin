package examples.hybrid

import akka.actor.{ActorRef, ActorSystem, Props}
import examples.commons.SimpleBoxTransaction
import examples.hybrid.blocks.{HybridBlock, PosBlock, PowBlock}
import examples.hybrid.settings.HybridMiningSettings
import examples.hybrid.state.CommitteeMember.HistoryModified
import examples.hybrid.state.CommitteeMember
import examples.hybrid.transaction.TreasuryTxForger.SuccessfullStateModification
import scorex.core.consensus.{HistoryReader, SyncInfo}
import scorex.core.transaction.{MempoolReader, Transaction}
import scorex.core.{LocalInterface, ModifierId, PersistentNodeViewModifier}
import scorex.core.transaction.box.proposition.PublicKey25519Proposition
import scorex.core.transaction.state.StateReader

class HLocalInterface(override val viewHolderRef: ActorRef,
                      powMinerRef: ActorRef,
                      posForgerRef: ActorRef,
                      treasuryTxsForgerRef: ActorRef,
                      minerSettings: HybridMiningSettings)
  extends LocalInterface[PublicKey25519Proposition, SimpleBoxTransaction, HybridBlock] {

  import examples.hybrid.mining.PosForger.ReceivableMessages.{StartForging, StopForging}
  import examples.hybrid.mining.PowMiner.ReceivableMessages.{MineBlock, StartMining, StopMining}

  private var block = false

  override protected def onStartingPersistentModifierApplication(pmod: HybridBlock): Unit = {}

  override protected def onFailedTransaction(tx: SimpleBoxTransaction): Unit = {}

  override protected def onSyntacticallyFailedModification(mod: HybridBlock): Unit = {}

  override protected def onSuccessfulTransaction(tx: SimpleBoxTransaction): Unit = {}

  override protected def onSyntacticallySuccessfulModification(mod: HybridBlock): Unit = {}

  override protected def onSemanticallyFailedModification(mod: HybridBlock): Unit = {}

  override protected def onNewSurface(newSurface: Seq[ModifierId]): Unit = {}

  override protected def onRollbackFailed(): Unit = {
    log.error("Too deep rollback occurred!")
  }

  override def onChangedState(r: StateReader): Unit = {
    treasuryTxsForgerRef ! SuccessfullStateModification
  }

  override def onChangedHistory(r: HistoryReader[_ <: PersistentNodeViewModifier, _ <: SyncInfo]): Unit = {

    CommitteeMember.manage(viewHolderRef) match {
      case Some(cm) => cm ! HistoryModified
      case None =>
    }
  }

  override def onChangedMempool(r: MempoolReader[_ <: Transaction[_]]): Unit = {}

  override def onChangedVault(): Unit = {}

  //stop PoW miner and start PoS forger if PoW block comes
  //stop PoW forger and start PoW miner if PoS block comes
  override protected def onSemanticallySuccessfulModification(mod: HybridBlock): Unit = {
    if (!block) {
      mod match {
        case wb: PowBlock =>
          posForgerRef ! StartForging
          powMinerRef ! MineBlock

        case sb: PosBlock =>
          if (!(sb.parentId sameElements minerSettings.GenesisParentId)) {
            posForgerRef ! StopForging
            powMinerRef ! StartMining
          }
      }
    }
  }

  override protected def onNoBetterNeighbour(): Unit = {
    powMinerRef ! StartMining
    posForgerRef ! StartForging
    block = false
  }

  override protected def onBetterNeighbourAppeared(): Unit = {
    powMinerRef ! StopMining
    posForgerRef ! StopForging
    block = true
  }
}

object HLocalInterfaceRef {
  def props(viewHolderRef: ActorRef,
            powMinerRef: ActorRef,
            posForgerRef: ActorRef,
            treasuryTxsForgerRef: ActorRef,
            minerSettings: HybridMiningSettings): Props =
    Props(new HLocalInterface(viewHolderRef, powMinerRef, posForgerRef, treasuryTxsForgerRef, minerSettings))

  def apply(viewHolderRef: ActorRef,
            powMinerRef: ActorRef,
            posForgerRef: ActorRef,
            treasuryTxsForgerRef: ActorRef,
            minerSettings: HybridMiningSettings)
           (implicit system: ActorSystem): ActorRef =
    system.actorOf(props(viewHolderRef, powMinerRef, posForgerRef, treasuryTxsForgerRef, minerSettings))

  def apply(name: String, viewHolderRef: ActorRef,
            powMinerRef: ActorRef,
            posForgerRef: ActorRef,
            treasuryTxsForgerRef: ActorRef,
            minerSettings: HybridMiningSettings)
           (implicit system: ActorSystem): ActorRef =
    system.actorOf(props(viewHolderRef, powMinerRef, posForgerRef, treasuryTxsForgerRef, minerSettings), name)
}
