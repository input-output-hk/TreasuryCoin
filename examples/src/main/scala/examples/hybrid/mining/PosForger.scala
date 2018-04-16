package examples.hybrid.mining

import akka.actor.{Actor, ActorRef, ActorSystem, Props}
import examples.commons.{PublicKey25519NoncedBox, SimpleBoxTransaction, SimpleBoxTransactionMemPool}
import examples.hybrid.HybridNodeViewHolder.{CurrentViewWithTreasuryState, GetDataFromCurrentViewWithTreasuryState}
import examples.hybrid.TreasuryManager
import examples.hybrid.blocks.{HybridBlock, PosBlock, PowBlock}
import examples.hybrid.history.HybridHistory
import examples.hybrid.settings.HybridSettings
import examples.hybrid.state.{HBoxStoredState, TreasuryTxValidator}
import examples.hybrid.transaction.mandatory.{PaymentTransaction, PenaltyTransaction}
import examples.hybrid.wallet.HWallet
import scorex.core.transaction.state.PrivateKey25519
import scorex.core.utils.ScorexLogging
import scorex.crypto.hash.Blake2b256
import scorex.utils.Random

import scala.util.{Failure, Success, Try}


class PosForger(settings: HybridSettings, viewHolderRef: ActorRef) extends Actor with ScorexLogging {

  import PosForger._
  import PosForger.ReceivableMessages._
  import scorex.core.NodeViewHolder.ReceivableMessages.LocallyGeneratedModifier


  var forging = false

  override def receive: Receive = {
    case StartForging =>
      forging = true
      viewHolderRef ! getRequiredData

    case pfi: PosForgingInfo =>
      val target = settings.mining.MaxTarget / pfi.diff

      val boxKeys = pfi.boxKeys

      //last check on whether to forge at all
      if (pfi.pairCompleted) {
        self ! StopForging
      } else {
        val powBlock = pfi.bestPowBlock
        log.debug(s"Trying to generate PoS block on top of ${powBlock.encodedId} with balance " +
          s"${boxKeys.map(_._1.value.toLong).sum}")
        val attachment = Random.randomBytes(settings.mining.posAttachmentSize)
        posIteration(powBlock, boxKeys, pfi.txsToInclude, attachment, target) match {
          case Some(posBlock) =>
            log.debug(s"Locally generated PoS block: $posBlock")
            forging = false
            viewHolderRef !
              LocallyGeneratedModifier[HybridBlock](posBlock)
          case None =>
            log.debug(s"Failed to generate PoS block")
        }
      }

    case StopForging =>
      forging = false
  }
}

object PosForger extends ScorexLogging {

  val InitialDifficuly = 1500000000L

  object ReceivableMessages {
    case object StartForging
    case object StopForging
    case class PosForgingInfo(pairCompleted: Boolean,
                              bestPowBlock: PowBlock,
                              diff: BigInt,
                              boxKeys: Seq[(PublicKey25519NoncedBox, PrivateKey25519)],
                              txsToInclude: Seq[SimpleBoxTransaction])
  }

  import ReceivableMessages.PosForgingInfo

  def hit(pwb: PowBlock)(box: PublicKey25519NoncedBox): BigInt = {
    val h = Blake2b256(pwb.bytes ++ box.bytes)
    BigInt(1, h)
  }

  def posIteration(powBlock: PowBlock,
                   boxKeys: Seq[(PublicKey25519NoncedBox, PrivateKey25519)],
                   txsToInclude: Seq[SimpleBoxTransaction],
                   attachment: Array[Byte],
                   target: BigInt
                  ): Option[PosBlock] = {
    val successfulHits = boxKeys.map { boxKey =>
      val h = hit(powBlock)(boxKey._1)
      (boxKey, h)
    }.filter(t => t._2 < t._1._1.value * target)

    log.info(s"Successful hits: ${successfulHits.size}")

    successfulHits.headOption.map { case (boxKey, _) =>
      PosBlock.create(
        powBlock.id,
        System.currentTimeMillis(),
        txsToInclude,
        boxKey._1,
        attachment,
        boxKey._2)
    }
  }

  val getRequiredData: GetDataFromCurrentViewWithTreasuryState[HybridHistory,
    HBoxStoredState,
    HWallet,
    SimpleBoxTransactionMemPool,
    PosForgingInfo] = {
    val f: CurrentViewWithTreasuryState[HybridHistory, HBoxStoredState, HWallet, SimpleBoxTransactionMemPool] => PosForgingInfo = {
      view: CurrentViewWithTreasuryState[HybridHistory, HBoxStoredState, HWallet, SimpleBoxTransactionMemPool] =>

        val diff = view.history.posDifficulty
        val pairCompleted = view.history.pairCompleted
        val bestPowBlock = view.history.bestPowBlock
        val boxes = view.vault.boxes().map(_.box).filter(box => view.state.closedBox(box.id).isDefined)
        val boxKeys = boxes.flatMap(b => view.vault.secretByPublicImage(b.proposition).map(s => (b, s)))

        val blockHeight = view.history.storage.heightOf(bestPowBlock.id).get + 1
        val treasuryTxValidatorTry = Try(new TreasuryTxValidator(view.trState, blockHeight, Some(view.history), Some(view.state)))

        val txs = view.pool.take(TransactionsPerBlock).foldLeft(Seq[SimpleBoxTransaction]()) { case (collected, tx) =>
          if (view.state.validate(tx).isSuccess &&
            tx.boxIdsToOpen.forall(id => !collected.flatMap(_.boxIdsToOpen)
              .exists(_ sameElements id))) collected :+ tx
          else collected
        }

        val paymentTx =
          if ((blockHeight % TreasuryManager.EPOCH_LEN) == TreasuryManager.PAYMENT_BLOCK_HEIGHT) {
            // Mandatory PaymentTransaction at the specific height
            PaymentTransaction.create(view.trState, view.history, view.state).toOption
          } else None

        val penaltyTx =
          if ((blockHeight % TreasuryManager.EPOCH_LEN) == TreasuryManager.PENALTY_BLOCK_HEIGHT) {
            // Mandatory PenaltyTransaction at the specific height
            PenaltyTransaction.create(view.trState, view.history, view.state).toOption
          } else None

        // currently we allow only 1 treasury tx per block (cause they may be too heavy).
        // TODO: if more than 1 tx is allowed then probably we also need to check that treasury txs from pool are consistent with each other (no duplicates, etc.)
        val treasuryTx = view.pool.takeTreasuryTxs(50).find(t => treasuryTxValidatorTry.flatMap(_.validate(t)).isSuccess)

        val allTxs = txs ++ paymentTx.toIterable ++ penaltyTx.toIterable ++ treasuryTx.toIterable

        PosForgingInfo(pairCompleted, bestPowBlock, diff, boxKeys, allTxs)
    }
    GetDataFromCurrentViewWithTreasuryState[HybridHistory,
      HBoxStoredState,
      HWallet,
      SimpleBoxTransactionMemPool,
      PosForgingInfo](f)

  }

  val TransactionsPerBlock = 50

}

object PosForgerRef {
  def props(settings: HybridSettings, viewHolderRef: ActorRef): Props = Props(new PosForger(settings, viewHolderRef))
  def apply(settings: HybridSettings, viewHolderRef: ActorRef)
           (implicit system: ActorSystem): ActorRef = system.actorOf(props(settings, viewHolderRef))
  def apply(name: String, settings: HybridSettings, viewHolderRef: ActorRef)
           (implicit system: ActorSystem): ActorRef = system.actorOf(props(settings, viewHolderRef), name)
}
