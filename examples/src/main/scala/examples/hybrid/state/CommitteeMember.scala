package examples.hybrid.state

import java.math.BigInteger

import akka.actor.{Actor, ActorRef, ActorSystem, PoisonPill, Props}
import akka.util.Timeout
import examples.commons.SimpleBoxTransactionMemPool
import examples.hybrid.HybridNodeViewHolder.{CurrentViewWithTreasuryState, GetDataFromCurrentViewWithTreasuryState}
import examples.hybrid.TreasuryManager
import examples.hybrid.TreasuryManager.Role
import examples.hybrid.history.HybridHistory
import examples.hybrid.state.CommitteeMember.{HistoryModified, TxInfo}
import examples.hybrid.transaction.{DKGr1Transaction, TreasuryTransaction}
import examples.hybrid.wallet.HWallet
import scorex.core.LocalInterface.LocallyGeneratedTransaction
import scorex.core.transaction.box.proposition.PublicKey25519Proposition
import scorex.core.utils.ScorexLogging
import treasury.crypto.core.{KeyPair, SimpleIdentifier}
import treasury.crypto.keygen.DistrKeyGen

import scala.concurrent.Await
import scala.util.{Success, Try}

class CommitteeMember(viewHolderRef: ActorRef) extends Actor with ScorexLogging {

  type NodeView = CommitteeMember.NodeView

  private val getTransaction: GetDataFromCurrentViewWithTreasuryState[HybridHistory,
    HBoxStoredState,
    HWallet,
    SimpleBoxTransactionMemPool,
    TxInfo] = {

    val f = (view: NodeView) => TxInfo(getTx(view))

    GetDataFromCurrentViewWithTreasuryState[HybridHistory,
      HBoxStoredState,
      HWallet,
      SimpleBoxTransactionMemPool,
      TxInfo](f)
  }

  override def receive: Receive = {
    case ti: TxInfo =>
      ti.tx match {
        case Some(tx) =>
          log.info(s"Generated tx ${tx.getClass.getName}")
          viewHolderRef ! LocallyGeneratedTransaction[PublicKey25519Proposition, TreasuryTransaction](tx)

        case None =>
          log.info(s"Hasn't generated tx")
      }

    case HistoryModified => viewHolderRef ! getTransaction
  }

  private var roundNum = 0 // is used to avoid repeated calls of the same round functions

  private def getTx(view: NodeView): Option[TreasuryTransaction] = {
    import examples.hybrid.TreasuryManager._
    val epochHeight = view.history.height % TreasuryManager.EPOCH_LEN

    epochHeight match {

      case h if DISTR_KEY_GEN_R1_RANGE.contains(h) && (roundNum == 0 || roundNum == 2) =>

        dkgOpt = initDKG(view)
        val tx = round1DkgTx(dkgOpt, view)

        tx match {
          case Some(_) =>
//            log.info(s"R1Data transaction is generated successfully")
            roundNum = 1
            tx

          case _ =>
//            log.info(s"[ERROR] R1Data transaction wasn't generated!")
            None
        }

      case h if DISTR_KEY_GEN_R2_RANGE.contains(h) && roundNum == 1 =>

//        log.info(s"R2Data transaction is generated successfully")
        roundNum = 2
        round2DkgTx(dkgOpt, view)

      case _ =>
        log.info(s"Current height: ${epochHeight}; roundNum: ${roundNum}")
        None
    }
  }

  private var dkgOpt: Option[DistrKeyGen] = None
  private var ownKeyPair: Option[KeyPair] = None

  private def initDKG(view: NodeView): Option[DistrKeyGen] = {

    val cs = view.trState.cs

    val crs_h = cs.basePoint.multiply(BigInteger.valueOf(5)) // common CRS parameter (temporary)

    val committeeMembersPubKeys = view.trState.getCommitteeProxyKeys
    val memberIdentifier = new SimpleIdentifier(committeeMembersPubKeys)

    val keyPair = view.vault.treasuryCommitteeSecrets(view.trState.epochNum)

    ownKeyPair =
      if (keyPair.nonEmpty) Some(keyPair.head.privKey, keyPair.head.pubKey)
      else None

    if (ownKeyPair.isDefined)
      Some(
        new DistrKeyGen(cs,
          crs_h,
          (ownKeyPair.get._1, ownKeyPair.get._2),
          committeeMembersPubKeys,
          memberIdentifier))
    else
      None
  }

  private def validateTx(view: NodeView, tx: TreasuryTransaction): Boolean = {

    val pending = tx match {
      case txToValidate: DKGr1Transaction =>
        view.pool.unconfirmed.values.exists {
          case txPool: DKGr1Transaction => txPool.pubKey == txToValidate.pubKey
          case _ => false
      }
      case _ => false
    }
    val isValid = Try(new TreasuryTxValidator(view.trState, view.history.height)).flatMap(_.validate(tx)).isSuccess
    !pending && isValid
  }

  private def round1DkgTx(dkgOpt: Option[DistrKeyGen], view: NodeView): Option[TreasuryTransaction] = {

    println("DKG Round1 started")

    dkgOpt match {
      case Some(dkg) =>

        // Use transport key pair also as own secret key pair in DKG protocol
        val privateKey = ownKeyPair.get._1 // dkg can't be created without ownKeyPair, so verification for ownKeyPair existence isn't needed here
        val r1Data = dkg.doRound1(privateKey.toByteArray)

        val signingKeyOpt = view.vault.treasurySigningSecrets(Role.Committee, view.trState.epochNum).headOption

        signingKeyOpt match {
          case Some(signingKey) =>
            DKGr1Transaction.create(signingKey.privKey, r1Data, view.trState.epochNum) match {
              case Success(tx) if validateTx(view, tx) => Some(tx)
              case _ => None
            }
          case _ => None
        }
      case _ => None
    }
  }

  private def round2DkgTx(dkgOpt: Option[DistrKeyGen], view: NodeView): Option[TreasuryTransaction] = {

    println("DKG Round2 started")

    None
  }
}

object CommitteeMember {

  type NodeView = CurrentViewWithTreasuryState[HybridHistory, HBoxStoredState, HWallet, SimpleBoxTransactionMemPool]

  case class TxInfo(tx: Option[TreasuryTransaction])

  case object HistoryModified

  private var committeeMember: Option[ActorRef] = None
  implicit val system = ActorSystem()

  def manage(viewHolderRef: ActorRef): Option[ActorRef] = {

    def getCurrentView: Try[NodeView] = Try {

      def f(view: NodeView): NodeView = view

      import akka.pattern.ask
      import scala.concurrent.duration._

      implicit val duration: Timeout = 20 seconds

      Await.result(viewHolderRef ? GetDataFromCurrentViewWithTreasuryState[HybridHistory,
        HBoxStoredState,
        HWallet,
        SimpleBoxTransactionMemPool,
        NodeView](f), 5.seconds).asInstanceOf[NodeView]
    }

    def isRegisteredAsCommitteeMember(view: NodeView): Boolean = {

      val localSigningPubKeyOpt = view.vault.treasurySigningPubKeys(Role.Committee, view.trState.epochNum).headOption

      // Check if current epoch treasury state contains given signing public key (this means the key is registered)
      localSigningPubKeyOpt match {
        case Some(localSigningPubKey) =>
          view.trState.getCommitteeSigningKeys.contains(localSigningPubKey)
        case None => false
      }
    }

    val currentView = getCurrentView

    if (currentView.isSuccess &&
        isRegisteredAsCommitteeMember(currentView.get)) {

      val history = currentView.get.history

      import examples.hybrid.TreasuryManager._
      val epochHeight = history.height % TreasuryManager.EPOCH_LEN

      if (epochHeight >= DISTR_KEY_GEN_R1_RANGE.start &&
          epochHeight <  PAYMENT_BLOCK_HEIGHT) {

        committeeMember match {
          case None => committeeMember = Some(CommitteeMemberRef(viewHolderRef))
          case Some(_) =>
        }
      } else {

        committeeMember match {
          case Some(cm) =>
            cm ! PoisonPill
            committeeMember = None
          case None =>
        }
      }
    }
    committeeMember
  }
}

object CommitteeMemberRef {

  def props(viewHolderRef: ActorRef): Props = Props(new CommitteeMember(viewHolderRef))

  def apply(viewHolderRef: ActorRef)
           (implicit system: ActorSystem): ActorRef = system.actorOf(props(viewHolderRef))

  def apply(name: String, viewHolderRef: ActorRef)
           (implicit system: ActorSystem): ActorRef = system.actorOf(props(viewHolderRef), name)
}
