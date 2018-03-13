package examples.hybrid.state

import java.math.BigInteger

import akka.actor.{Actor, ActorRef, ActorSystem, PoisonPill, Props}
import akka.util.Timeout
import examples.commons.SimpleBoxTransactionMemPool
import examples.hybrid.HybridNodeViewHolder.{CurrentViewWithTreasuryState, GetDataFromCurrentViewWithTreasuryState}
import examples.hybrid.TreasuryManager
import examples.hybrid.TreasuryManager._
import examples.hybrid.history.HybridHistory
import examples.hybrid.state.CommitteeMember.{HistoryModified, TxInfo}
import examples.hybrid.transaction.DKG._
import examples.hybrid.transaction._
import examples.hybrid.wallet.HWallet
import scorex.core.LocallyGeneratedModifiersMessages.ReceivableMessages.LocallyGeneratedTransaction
import scorex.core.transaction.box.proposition.PublicKey25519Proposition
import scorex.core.transaction.state.PrivateKey25519
import scorex.core.utils.ScorexLogging
import scorex.crypto.encode.Base58
import treasury.crypto.core.{KeyPair, PubKey, SimpleIdentifier}
import treasury.crypto.keygen.datastructures.round1.R1Data
import treasury.crypto.keygen.datastructures.round2.R2Data
import treasury.crypto.keygen.datastructures.round3.R3Data
import treasury.crypto.keygen.datastructures.round4.R4Data
import treasury.crypto.keygen.datastructures.round5_2.SecretKey
import treasury.crypto.keygen.{DistrKeyGen, RoundsData}

import scala.concurrent.Await
import scala.util.{Failure, Success, Try}

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

  def synchronizeState(epochHeight: Long, view: NodeView, dkgOptIn: Option[DistrKeyGen]): Option[DistrKeyGen] = {

    var dkgOpt: Option[DistrKeyGen] = dkgOptIn
    var ownDataInMempool = RoundsData()

    if (dkgOpt.isDefined) {

      val roundsPassed = epochHeight match {

        case h if DISTR_KEY_GEN_R1_RANGE.contains(h) =>

          val roundNumber = 1

          // get own data for round 1 from mempool, if any
          ownDataInMempool = getOwnRoundDataFromMempool(roundNumber, view)
          val ownDataInState = getOwnRoundDataFromState(roundNumber, view)

          require(!(ownDataInMempool.r1Data.nonEmpty && ownDataInState.r1Data.nonEmpty), s"R$roundNumber data exists both in mempool and state")

          if (ownDataInMempool.r1Data.nonEmpty || ownDataInState.r1Data.nonEmpty) roundNumber // round data is already posted, so there is a need to restore the current round state
          else roundNumber - 1

        case h if DISTR_KEY_GEN_R2_RANGE.contains(h) =>

          val roundNumber = 2

          // get own data for round 1 from mempool, if any
          ownDataInMempool = getOwnRoundDataFromMempool(roundNumber, view)
          val ownDataInState = getOwnRoundDataFromState(roundNumber, view)

          require(!(ownDataInMempool.r2Data.nonEmpty && ownDataInState.r2Data.nonEmpty), s"R$roundNumber data exists both in mempool and state")

          if (ownDataInMempool.r2Data.nonEmpty || ownDataInState.r2Data.nonEmpty) roundNumber // round data is already posted, so there is a need to restore the current round state
          else roundNumber - 1

        case h if DISTR_KEY_GEN_R3_RANGE.contains(h) =>

          val roundNumber = 3

          // get own data for round 1 from mempool, if any
          ownDataInMempool = getOwnRoundDataFromMempool(roundNumber, view)
          val ownDataInState = getOwnRoundDataFromState(roundNumber, view)

          require(!(ownDataInMempool.r3Data.nonEmpty && ownDataInState.r3Data.nonEmpty), s"R$roundNumber data exists both in mempool and state")

          if (ownDataInMempool.r3Data.nonEmpty || ownDataInState.r3Data.nonEmpty) roundNumber // round data is already posted, so there is a need to restore the current round state
          else roundNumber - 1

        case h if DISTR_KEY_GEN_R4_RANGE.contains(h) =>

          val roundNumber = 4

          // get own data for round 1 from mempool, if any
          ownDataInMempool = getOwnRoundDataFromMempool(roundNumber, view)
          val ownDataInState = getOwnRoundDataFromState(roundNumber, view)

          require(!(ownDataInMempool.r4Data.nonEmpty && ownDataInState.r4Data.nonEmpty), s"R$roundNumber data exists both in mempool and state")

          if (ownDataInMempool.r4Data.nonEmpty || ownDataInState.r4Data.nonEmpty) roundNumber // round data is already posted, so there is a need to restore the current round state
          else roundNumber - 1

        case h if DISTR_KEY_GEN_R5_RANGE.contains(h) =>

          val roundNumber = 5

          // get own data for round 1 from mempool, if any
          ownDataInMempool = getOwnRoundDataFromMempool(roundNumber, view)
          val ownDataInState = getOwnRoundDataFromState(roundNumber, view)

          require(!(ownDataInMempool.r5_1Data.nonEmpty && ownDataInState.r5_1Data.nonEmpty), s"R$roundNumber data exists both in mempool and state")

          if (ownDataInMempool.r5_1Data.nonEmpty || ownDataInState.r5_1Data.nonEmpty) roundNumber // round data is already posted, so there is a need to restore the current round state
          else roundNumber - 1

        case h if h >= DISTR_KEY_GEN_R5_RANGE.end =>

          val roundNumber = 6

          sharedPublicKeyOpt match {
            case Some(_) => roundNumber // if sharedPublicKeyOpt is defined, then dkg state is already updated to round 6, so desync will not occur
            case _ => roundNumber - 1
          }

        case _ => 0
      }

      if (dkgOpt.get.getRoundsPassed != roundsPassed) {

        log.info(s"State need to be restored: ${dkgOpt.get.getRoundsPassed} - $roundsPassed")

        if (dkgOpt.get.getRoundsPassed != 0){ // re-initialize dkg, if it is in state other than initial
          dkgOpt = initDKG(view)
        }

        val roundsShouldBePassed = {
          if (roundsPassed > 5) 5 // state can be restored only up to the 5-th round. Round 6 is virtual and should be executed externally.
          else roundsPassed
        }

        if (dkgOpt.isDefined) { // check after possible re-initialization

          val privateKey = ownKeyPairOpt.get._1 // dkg can't be created without ownKeyPairOpt, so verification for ownKeyPairOpt existence isn't needed here

          val roundsData = RoundsData(
            view.trState.getDKGr1Data.values.toSeq ++ ownDataInMempool.r1Data,
            view.trState.getDKGr2Data.values.toSeq ++ ownDataInMempool.r2Data,
            view.trState.getDKGr3Data.values.toSeq ++ ownDataInMempool.r3Data,
            view.trState.getDKGr4Data.values.toSeq ++ ownDataInMempool.r4Data,
            view.trState.getDKGr5Data.values.toSeq ++ ownDataInMempool.r5_1Data
          )

          dkgOpt.get.setState(privateKey.toByteArray, roundsData) match {

            case Failure(_) => dkgOpt = None
            case _ => if (dkgOpt.get.getRoundsPassed != roundsShouldBePassed) dkgOpt = None
          }
        }
      }
    }
    dkgOpt
  }

  def getOwnRoundDataFromState(roundNum: Int, view: NodeView): RoundsData = {

    val roundsData = RoundsData()

    ownSigningKeyPairOpt match {
      case Some(ownSigningKeyPair) =>

        val signingPubKey = ownSigningKeyPair.publicImage
        val ownId = view.trState.getApprovedCommitteeInfo.indexWhere(_.signingKey == signingPubKey)

        roundNum match {

          case 1 =>
            val r1DataOpt = view.trState.getDKGr1Data.find(_._1 == ownId)
            if (r1DataOpt.isDefined)
              roundsData.r1Data = Seq(r1DataOpt.get._2)

          case 2 =>
            val r2DataOpt = view.trState.getDKGr2Data.find(_._1 == ownId)
            if (r2DataOpt.isDefined)
              roundsData.r2Data = Seq(r2DataOpt.get._2)

          case 3 =>
            val r3DataOpt = view.trState.getDKGr3Data.find(_._1 == ownId)
            if (r3DataOpt.isDefined)
              roundsData.r3Data = Seq(r3DataOpt.get._2)

          case 4 =>
            val r4DataOpt = view.trState.getDKGr4Data.find(_._1 == ownId)
            if (r4DataOpt.isDefined)
              roundsData.r4Data = Seq(r4DataOpt.get._2)

          case 5 =>
            val r5DataOpt = view.trState.getDKGr5Data.find(_._1 == ownId)
            if (r5DataOpt.isDefined)
              roundsData.r5_1Data = Seq(r5DataOpt.get._2)

          case _ =>
        }
      case _ =>
    }
    roundsData
  }

  def getOwnRoundDataFromMempool(roundNum: Int, view: NodeView): RoundsData = {

    val roundsData = RoundsData()

    ownSigningKeyPairOpt match {
      case Some(ownSigningKeyPair) =>

        val signingPubKey = ownSigningKeyPair.publicImage

        roundNum match {

          case 1 =>
            val r1TxOpt = view.pool.unconfirmed.values.find {
              case txPool: DKGr1Transaction => txPool.pubKey == signingPubKey
              case _ => false
            }
            r1TxOpt match {
              case Some(r1Tx: DKGr1Transaction) =>
                roundsData.r1Data = Seq(r1Tx.r1Data)
              case _ =>
            }

          case 2 =>
            val r2TxOpt = view.pool.unconfirmed.values.find {
              case txPool: DKGr2Transaction => txPool.pubKey == signingPubKey
              case _ => false
            }
            r2TxOpt match {
              case Some(r2Tx: DKGr2Transaction) =>
                roundsData.r2Data = Seq(r2Tx.r2Data)
              case _ =>
            }

          case 3 =>
            val r3TxOpt = view.pool.unconfirmed.values.find {
              case txPool: DKGr3Transaction => txPool.pubKey == signingPubKey
              case _ => false
            }
            r3TxOpt match {
              case Some(r3Tx: DKGr3Transaction) =>
                roundsData.r3Data = Seq(r3Tx.r3Data)
              case _ =>
            }

          case 4 =>
            val r4TxOpt = view.pool.unconfirmed.values.find {
              case txPool: DKGr4Transaction => txPool.pubKey == signingPubKey
              case _ => false
            }
            r4TxOpt match {
              case Some(r4Tx: DKGr4Transaction) =>
                roundsData.r4Data = Seq(r4Tx.r4Data)
              case _ =>
            }

          case 5 =>
            val r5TxOpt = view.pool.unconfirmed.values.find {
              case txPool: DKGr5Transaction => txPool.pubKey == signingPubKey
              case _ => false
            }
            r5TxOpt match {
              case Some(r5Tx: DKGr5Transaction) =>
                roundsData.r5_1Data = Seq(r5Tx.r5_1Data)
              case _ =>
            }

          case _ =>
        }
      case _ =>
    }
    roundsData
  }

  def roundDataIsPosted(roundNum: Int, view: NodeView): Boolean = {

    ownSigningKeyPairOpt match {
      case Some(ownSigningKeyPair) =>

        val signingPubKey = ownSigningKeyPair.publicImage

        val pending = roundNum match {
          case 1 =>
            view.pool.unconfirmed.values.exists {
              case txPool: DKGr1Transaction => txPool.pubKey == signingPubKey
              case _ => false
            }
          case 2 =>
            view.pool.unconfirmed.values.exists {
              case txPool: DKGr2Transaction => txPool.pubKey == signingPubKey
              case _ => false
            }
          case 3 =>
            view.pool.unconfirmed.values.exists {
              case txPool: DKGr3Transaction => txPool.pubKey == signingPubKey
              case _ => false
            }
          case 4 =>
            view.pool.unconfirmed.values.exists {
              case txPool: DKGr4Transaction => txPool.pubKey == signingPubKey
              case _ => false
            }
          case 5 =>
            view.pool.unconfirmed.values.exists {
              case txPool: DKGr5Transaction => txPool.pubKey == signingPubKey
              case _ => false
            }
          case _ => false
        }

        val ownId = view.trState.getApprovedCommitteeInfo.indexWhere(_.signingKey == signingPubKey)

        val accepted = roundNum match {
          case 1 => view.trState.getDKGr1Data.contains(ownId)
          case 2 => view.trState.getDKGr2Data.contains(ownId)
          case 3 => view.trState.getDKGr3Data.contains(ownId)
          case 4 => view.trState.getDKGr4Data.contains(ownId)
          case 5 => view.trState.getDKGr5Data.contains(ownId)
          case _ => false
        }
        pending || accepted

      case _ => false // no any data could have been posted without own signing key pair
    }
  }

  private def getTx(view: NodeView): Option[TreasuryTransaction] = {
    import examples.hybrid.TreasuryManager._
    val epochHeight = view.history.height % TreasuryManager.EPOCH_LEN

    if (dkgOpt.isEmpty)
      dkgOpt = initDKG(view)

    dkgOpt = synchronizeState(epochHeight, view, dkgOpt)

    if (dkgOpt.isDefined) {

      log.info(s"State is OK: ${dkgOpt.get.getRoundsPassed}")

      epochHeight match {

        case h if DISTR_KEY_GEN_R1_RANGE.contains(h) && !roundDataIsPosted(1, view) =>

          val tx = round1DkgTx(dkgOpt, view)

          tx match {
            case Some(_) =>
              log.info(s"R1Data transaction is generated successfully")
              tx

            case _ =>
              log.info(s"[ERROR] R1Data transaction wasn't generated!")
              None
          }

        case h if DISTR_KEY_GEN_R2_RANGE.contains(h) && !roundDataIsPosted(2, view) =>

          val r1DataSeq = view.trState.getDKGr1Data.values.toSeq
          val tx = round2DkgTx(r1DataSeq, dkgOpt, view)

          tx match {
            case Some(_) =>
              log.info(s"R2Data transaction is generated successfully")
              tx

            case _ =>
              log.info(s"[ERROR] R2Data transaction wasn't generated!")
              None
          }

        case h if DISTR_KEY_GEN_R3_RANGE.contains(h) && !roundDataIsPosted(3, view) =>

          val r2DataSeq = view.trState.getDKGr2Data.values.toSeq
          val tx = round3DkgTx(r2DataSeq, dkgOpt, view)

          tx match {
            case Some(_) =>
              log.info(s"R3Data transaction is generated successfully")
              tx

            case _ =>
              log.info(s"[ERROR] R3Data transaction wasn't generated!")
              None
          }

        case h if DISTR_KEY_GEN_R4_RANGE.contains(h) && !roundDataIsPosted(4, view) =>

          val r3DataSeq = view.trState.getDKGr3Data.values.toSeq
          val tx = round4DkgTx(r3DataSeq, dkgOpt, view)

          tx match {
            case Some(_) =>
              log.info(s"R4Data transaction is generated successfully")
              tx

            case _ =>
              log.info(s"[ERROR] R4Data transaction wasn't generated!")
              None
          }

        case h if DISTR_KEY_GEN_R5_RANGE.contains(h) && !roundDataIsPosted(5, view) =>

          val r4DataSeq = view.trState.getDKGr4Data.values.toSeq
          val tx = round5DkgTx(r4DataSeq, dkgOpt, view)

          tx match {
            case Some(_) =>
              log.info(s"R5Data transaction is generated successfully")
              tx

            case _ =>
              log.info(s"[ERROR] R5Data transaction wasn't generated!")
              None
          }

        case h if h >= DISTR_KEY_GEN_R5_RANGE.end && sharedPublicKeyOpt.isEmpty =>

          // Just get shared public key and restored secret keys for internal state, without posting a transaction

          val r5DataSeq = view.trState.getDKGr5Data.values.toSeq

          dkgOpt match {
            case Some(dkg) =>

              dkg.doRound5_2(r5DataSeq) match {
                case Some(r6Data) =>
                  sharedPublicKeyOpt = Some(cs.decodePoint(r6Data.sharedPublicKey))
                  log.info(s"Shared public key: ${Base58.encode(sharedPublicKeyOpt.get.getEncoded(true))}")
                  dkgViolatorsSecretKeys = Some(r6Data.violatorsSecretKeys)
                case _ =>
              }
            case _ =>
          }
          None

        case _ =>
          log.info(s"Current height: ${epochHeight}; roundNum: ${roundNum}")
          None
      }
    } else { // !dkgOpt.isDefined
      log.info(s"ERROR: State wasn't restored!")
      None
    }
  }

  private var dkgOpt: Option[DistrKeyGen] = None
  private var ownKeyPairOpt: Option[KeyPair] = None
  private var ownSigningKeyPairOpt: Option[PrivateKey25519] = None
  private var sharedPublicKeyOpt: Option[PubKey] = None
  private var dkgViolatorsSecretKeys: Option[Array[SecretKey]] = None

  private def initDKG(view: NodeView): Option[DistrKeyGen] = {

    val cs = view.trState.cs
    val crs_h = view.trState.crs_h

    dkgViolatorsSecretKeys = None
    sharedPublicKeyOpt = None

    val committeeMembersPubKeys = view.trState.getApprovedCommitteeInfo.map(_.proxyKey)
    val memberIdentifier = new SimpleIdentifier(committeeMembersPubKeys)

    ownSigningKeyPairOpt = view.vault.treasurySigningSecrets(view.trState.epochNum).headOption match {
      case Some(treasurySecret) => Some(treasurySecret.privKey)
      case _ => None
    }

    ownKeyPairOpt = view.vault.treasuryCommitteeSecrets(view.trState.epochNum) match {
      case keyPair if keyPair.nonEmpty => Some(keyPair.head.privKey, keyPair.head.pubKey)
      case _ => None
    }

    ownKeyPairOpt match {
      case Some(ownKeyPair) =>
        Some(
          new DistrKeyGen(cs,
            crs_h,
            (ownKeyPair._1, ownKeyPair._2),
            committeeMembersPubKeys,
            memberIdentifier))
      case _ => None
    }
  }

  private def validateTx(view: NodeView, trsryTx: TreasuryTransaction): Boolean = {

    val pending = trsryTx match {

      case txToValidate: DKGr1Transaction =>
        view.pool.unconfirmed.values.exists {
          case txPool: DKGr1Transaction => txPool.pubKey == txToValidate.pubKey
          case _ => false
      }
      case txToValidate: DKGr2Transaction =>
        view.pool.unconfirmed.values.exists {
          case txPool: DKGr2Transaction => txPool.pubKey == txToValidate.pubKey
          case _ => false
        }
      case txToValidate: DKGr3Transaction =>
        view.pool.unconfirmed.values.exists {
          case txPool: DKGr3Transaction => txPool.pubKey == txToValidate.pubKey
          case _ => false
        }
      case txToValidate: DKGr4Transaction =>
        view.pool.unconfirmed.values.exists {
          case txPool: DKGr4Transaction => txPool.pubKey == txToValidate.pubKey
          case _ => false
        }
      case txToValidate: DKGr5Transaction =>
        view.pool.unconfirmed.values.exists {
          case txPool: DKGr5Transaction => txPool.pubKey == txToValidate.pubKey
          case _ => false
        }

      case _ => false
    }

    val isValid = Try(new TreasuryTxValidator(view.trState, view.history.height)).flatMap(_.validate(trsryTx)).isSuccess
    !pending && isValid
  }

  private def round1DkgTx(dkgOpt: Option[DistrKeyGen], view: NodeView): Option[TreasuryTransaction] = {

    println("DKG Round1 started")

    dkgOpt match {
      case Some(dkg) =>

        // Use transport key pair also as own secret key pair in DKG protocol
        val privateKey = ownKeyPairOpt.get._1 // dkg can't be created without ownKeyPairOpt, so verification for ownKeyPairOpt existence isn't needed here

        dkg.doRound1(privateKey.toByteArray) match {
          case Some(r1Data) =>

            ownSigningKeyPairOpt match {
              case Some(ownSigningKeyPair) =>

                DKGr1Transaction.create(ownSigningKeyPair, r1Data, view.trState.epochNum) match {
                  case Success(tx) if validateTx(view, tx) => Some(tx)
                  case _ => None
                }
              case _ => None
            }
          case _ => None
        }
      case _ => None
    }
  }

  private def round2DkgTx(r1Data: Seq[R1Data], dkgOpt: Option[DistrKeyGen], view: NodeView): Option[TreasuryTransaction] = {

    println("DKG Round2 started")

    dkgOpt match {
      case Some(dkg) =>

        dkg.doRound2(r1Data) match {
          case Some(r2Data) =>

            ownSigningKeyPairOpt match {
              case Some(ownSigningKeyPair) =>

                DKGr2Transaction.create(ownSigningKeyPair, r2Data, view.trState.epochNum) match {
                  case Success(tx) if validateTx(view, tx) => Some(tx)
                  case _ => None
                }
              case _ => None
            }
          case _ => None
        }
      case _ => None
    }
  }

  private def round3DkgTx(r2Data: Seq[R2Data], dkgOpt: Option[DistrKeyGen], view: NodeView): Option[TreasuryTransaction] = {

    println("DKG Round3 started")

    dkgOpt match {
      case Some(dkg) =>

        dkg.doRound3(r2Data) match {
          case Some(r3Data) =>

            ownSigningKeyPairOpt match {
              case Some(ownSigningKeyPair) =>

                DKGr3Transaction.create(ownSigningKeyPair, r3Data, view.trState.epochNum) match {
                  case Success(tx) if validateTx(view, tx) => Some(tx)
                  case _ => None
                }
              case _ => None
            }
          case _ => None
        }
      case _ => None
    }
  }

  private def round4DkgTx(r3Data: Seq[R3Data], dkgOpt: Option[DistrKeyGen], view: NodeView): Option[TreasuryTransaction] = {

    println("DKG Round4 started")

    dkgOpt match {
      case Some(dkg) =>

        dkg.doRound4(r3Data) match {
          case Some(r4Data) =>

            ownSigningKeyPairOpt match {
              case Some(ownSigningKeyPair) =>

                DKGr4Transaction.create(ownSigningKeyPair, r4Data, view.trState.epochNum) match {
                  case Success(tx) if validateTx(view, tx) => Some(tx)
                  case _ => None
                }
              case _ => None
            }
          case _ => None
        }
      case _ => None
    }
  }

  private def round5DkgTx(r4Data: Seq[R4Data], dkgOpt: Option[DistrKeyGen], view: NodeView): Option[TreasuryTransaction] = {

    println("DKG Round5 started")

    dkgOpt match {
      case Some(dkg) =>

        dkg.doRound5_1(r4Data) match {
          case Some(r5Data) =>

            ownSigningKeyPairOpt match {
              case Some(ownSigningKeyPair) =>

                DKGr5Transaction.create(ownSigningKeyPair, r5Data, view.trState.epochNum) match {
                  case Success(tx) if validateTx(view, tx) => Some(tx)
                  case _ => None
                }
              case _ => None
            }
          case _ => None
        }
      case _ => None
    }
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

      val localSigningPubKeyOpt = view.vault.treasurySigningSecrets(view.trState.epochNum).headOption.map(_.privKey.publicImage)

      // Check if current epoch treasury state contains given signing public key (this means the key is registered)
      localSigningPubKeyOpt match {
        case Some(localSigningPubKey) =>
          view.trState.getApprovedCommitteeInfo.exists(_.signingKey == localSigningPubKey)
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
