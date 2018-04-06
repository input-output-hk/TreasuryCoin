package examples.hybrid

import akka.actor.{ActorRef, ActorSystem, Props}
import examples.commons._
import examples.hybrid.HybridNodeViewHolder.{CurrentViewWithTreasuryState, GetDataFromCurrentViewWithTreasuryState}
import examples.hybrid.blocks._
import examples.hybrid.history.{HybridHistory, HybridSyncInfo}
import examples.hybrid.settings.HybridMiningSettings
import examples.hybrid.state.{HBoxStoredState, TreasuryState, TreasuryTxValidator}
import examples.hybrid.wallet.HWallet
import scorex.core.consensus.History.ProgressInfo
import scorex.core.network.NodeViewSynchronizer.ReceivableMessages._
import scorex.core.serialization.Serializer
import scorex.core.settings.ScorexSettings
import scorex.core.transaction.Transaction
import scorex.core.transaction.box.proposition.PublicKey25519Proposition
import scorex.core.transaction.state.{PrivateKey25519Companion, TransactionValidation}
import scorex.core.utils.{NetworkTimeProvider, ScorexLogging}
import scorex.core.{ModifierTypeId, NodeViewHolder, NodeViewModifier, VersionTag}
import scorex.crypto.encode.Base58
import scorex.crypto.signatures.PublicKey

import scala.annotation.tailrec
import scala.util.{Failure, Success, Try}


class HybridNodeViewHolder(settings: ScorexSettings,
                           minerSettings: HybridMiningSettings,
                           timeProvider: NetworkTimeProvider)
  extends NodeViewHolder[PublicKey25519Proposition, SimpleBoxTransaction, HybridBlock] {

  override val networkChunkSize: Int = settings.network.networkChunkSize

  override type SI = HybridSyncInfo

  override type HIS = HybridHistory
  override type MS = HBoxStoredState
  override type VL = HWallet
  override type MP = SimpleBoxTransactionMemPool

  type P = PublicKey25519Proposition
  type TX = SimpleBoxTransaction
  type PMOD = HybridBlock

  private var treasuryState = TreasuryState.generate(history, history.bestBlock.id).get

  override val modifierSerializers: Map[ModifierTypeId, Serializer[_ <: NodeViewModifier]] =
    Map(PosBlock.ModifierTypeId -> PosBlockCompanion,
      PowBlock.ModifierTypeId -> PowBlockCompanion,
      Transaction.ModifierTypeId -> SimpleBoxTransactionCompanion)

  override def preRestart(reason: Throwable, message: Option[Any]): Unit = {
    super.preRestart(reason, message)
    log.error("HybridNodeViewHolder has been restarted, not a valid situation!")
    reason.printStackTrace()
    System.exit(100) // this actor shouldn't be restarted at all so kill the whole app if that happened
  }

  /**
    * Hard-coded initial view all the honest nodes in a network are making progress from.
    */
  override protected def genesisState: (HIS, MS, VL, MP) =
    HybridNodeViewHolder.generateGenesisState(settings, minerSettings, timeProvider)

  /**
    * Restore a local view during a node startup. If no any stored view found
    * (e.g. if it is a first launch of a node) None is to be returned
    */
  override def restoreState(): Option[(HIS, MS, VL, MP)] = {
    if (HWallet.exists(settings)) {
      Some((
        HybridHistory.readOrGenerate(settings, minerSettings, timeProvider),
        HBoxStoredState.readOrGenerate(settings),
        HWallet.readOrGenerate(settings, 1),
        SimpleBoxTransactionMemPool.emptyPool))
    } else None
  }

  override protected def txModify(tx: SimpleBoxTransaction): Unit = {
    //todo: async validation?
    val treasuryTxValidatorTry = Try(new TreasuryTxValidator(treasuryState, history().height, Some(history), Some(minimalState)))

    val errorOpt: Option[Throwable] = minimalState() match {
      case txValidator: TransactionValidation[P, TX] =>
        txValidator.validate(tx) match {
          case Success(_) => treasuryTxValidatorTry.flatMap(_.validate(tx)) match {
            case Success(_) => None
            case Failure(e) =>
              log.warn(s"Unconfirmed transactions $tx can not be validated by treasury state. Tx was not added to the memory pool.", e)
              Some(e)
          }
          case Failure(e) => Some(e)
        }
      case _ => None
    }

    errorOpt match {
      case None =>
        memoryPool().put(tx) match {
          case Success(newPool) =>
            log.debug(s"Unconfirmed transaction $tx added to the memory pool")
            val newVault = vault().scanOffchain(tx)
            updateNodeView(updatedVault = Some(newVault), updatedMempool = Some(newPool))
            context.system.eventStream.publish(SuccessfulTransaction[P, TX](tx))

          case Failure(e) =>
            context.system.eventStream.publish(FailedTransaction[P, TX](tx, e))
        }

      case Some(e) =>
        context.system.eventStream.publish(FailedTransaction[P, TX](tx, e))
    }
  }

  @tailrec
  override final def updateState(history: HIS,
                        state: MS,
                        progressInfo: ProgressInfo[PMOD],
                        suffixApplied: IndexedSeq[PMOD]): (HIS, Try[MS], Seq[PMOD]) = {
    requestDownloads(progressInfo)

    case class UpdateInformation(history: HIS,
                                 state: MS,
                                 trState: TreasuryState,
                                 failedMod: Option[PMOD],
                                 alternativeProgressInfo: Option[ProgressInfo[PMOD]],
                                 suffix: IndexedSeq[PMOD])

    val (stateToApplyTry: Try[MS], suffixTrimmed: IndexedSeq[PMOD]) = if (progressInfo.chainSwitchingNeeded) {
      val branchingPoint = VersionTag @@ progressInfo.branchPoint.get     //todo: .get
      if (!state.version.sameElements(branchingPoint)){
        state.rollbackTo(branchingPoint) -> trimChainSuffix(suffixApplied, branchingPoint)
      } else Success(state) -> IndexedSeq()
    } else Success(state) -> suffixApplied

    val epochNum = progressInfo.toApply.headOption
      .flatMap(b => history.storage.heightOf(b.id))
      .map(_ / TreasuryManager.EPOCH_LEN).getOrElse(-1)
    val trStateToApplyTry: Try[TreasuryState] =
      if ((epochNum != -1) && (treasuryState.epochNum != epochNum)) { // new epoch has been started, reset treasury state
        TreasuryState.generate(history, progressInfo.toApply.headOption.get.id)
      } else if (progressInfo.chainSwitchingNeeded) {
        val branchingPoint = VersionTag @@ progressInfo.branchPoint.get     //todo: .get
        treasuryState.rollback(branchingPoint, history).orElse(TreasuryState.generate(history, progressInfo.branchPoint.get))
      } else Try(treasuryState)

    (stateToApplyTry, trStateToApplyTry) match {
      case (Success(stateToApply), Success(trStateToApply)) =>

        val u0 = UpdateInformation(history, stateToApply, trStateToApply, None, None, suffixTrimmed)

        val uf = progressInfo.toApply.foldLeft(u0) {case (u, modToApply) =>
          if(u.failedMod.isEmpty) {
            u.trState.apply(modToApply, u.history) match {
              case Success(trStateAfterApply) =>
                u.state.applyModifier(modToApply) match {
                  case Success(stateAfterApply) =>
                    log.info(s"Successfull modifier: ${modToApply.encodedId}")
                    val newHis = history.reportModifierIsValid(modToApply)
                    context.system.eventStream.publish(SemanticallySuccessfulModifier(modToApply))
                    //updateState(newHis, stateAfterApply, newProgressInfo, suffixTrimmed :+ modToApply)
                    treasuryState = trStateAfterApply
                    UpdateInformation(newHis, stateAfterApply, trStateAfterApply, None, None, u.suffix :+ modToApply)
                  case Failure(e) =>
                    log.error("Invalid modifier for HBoxStoreState", e)
                    val (newHis, newProgressInfo) = history.reportModifierIsInvalid(modToApply, progressInfo)
                    context.system.eventStream.publish(SemanticallyFailedModification(modToApply, e))
                    //updateState(newHis, stateToApply, newProgressInfo, suffixTrimmed)
                    val lastValidMod = modToApply match {
                      case b: PowBlock => b.prevPosId
                      case b: PosBlock => b.parentId
                    }
                    treasuryState = treasuryState.rollback(VersionTag @@ lastValidMod, u.history)
                      .orElse(TreasuryState.generate(u.history, lastValidMod))
                      .getOrElse(treasuryState)
                    UpdateInformation(newHis, u.state, u.trState, Some(modToApply), Some(newProgressInfo), u.suffix)
                }
              case Failure(e) =>
                log.error("Invalid modifier for TreasuryState", e)
                val (newHis, newProgressInfo) = history.reportModifierIsInvalid(modToApply, progressInfo)
                context.system.eventStream.publish(SemanticallyFailedModification(modToApply, e))
                //updateState(newHis, stateToApply, newProgressInfo, suffixTrimmed)
                UpdateInformation(newHis, u.state, u.trState, Some(modToApply), Some(newProgressInfo), u.suffix)
            }
          } else u
        }

        uf.failedMod match {
          case Some(mod) => updateState(uf.history, uf.state, uf.alternativeProgressInfo.get, uf.suffix)
          case None => (uf.history, Success(uf.state), uf.suffix)
        }
      case (Failure(e), Success(_)) =>
        log.error("Rollback failed for HBoxStoredState: ", e)
        context.system.eventStream.publish(RollbackFailed)
        //todo: what to return here? the situation is totally wrong
        ???
      case (Success(_), Failure(e)) =>
        log.error("Rollback failed for TreasuryState: ", e)
        context.system.eventStream.publish(RollbackFailed)
        //todo: what to return here? the situation is totally wrong
        ???
      case (Failure(e1), Failure(e2)) =>
        log.error("Rollback failed for both TreasuryState and HBoxStoredState: ", e1)
        context.system.eventStream.publish(RollbackFailed)
        //todo: what to return here? the situation is totally wrong
        ???
    }
  }

  override def getCurrentInfo: Receive = {
    super.getCurrentInfo orElse {
      case GetDataFromCurrentViewWithTreasuryState(f) =>
        sender() ! f(CurrentViewWithTreasuryState(history(), minimalState(), vault(), memoryPool(), treasuryState))
    }
  }
}

object HybridNodeViewHolder extends ScorexLogging {

  case class GetDataFromCurrentViewWithTreasuryState[HIS, MS, VL, MP, A](f: CurrentViewWithTreasuryState[HIS, MS, VL, MP] => A)
  case class CurrentViewWithTreasuryState[HIS, MS, VL, MP](history: HIS, state: MS, vault: VL, pool: MP, trState: TreasuryState)

  def generateGenesisState(settings: ScorexSettings, minerSettings: HybridMiningSettings, timeProvider: NetworkTimeProvider):
                          (HybridHistory, HBoxStoredState, HWallet, SimpleBoxTransactionMemPool) = {
    val GenesisAccountsNum = 50
    val GenesisBalance = Value @@ 100000000L

    //propositions with wallet seed genesisoo, genesiso1, ..., genesis48, genesis49
    val icoMembers: IndexedSeq[PublicKey25519Proposition] = IndexedSeq(
      "6sYyiTguyQ455w2dGEaNbrwkAWAEYV1Zk6FtZMknWDKQ",
      "7BDhJv6Wh2MekgJLvQ98ot9xiw5x3N4b3KipURdrW8Ge",
      "Ei8oY3eg5vM26QUBhyFiAdPN1C23RJEV9irrykNmSAFV",
      "8LNhm5QagL88sWggvJKGDiZ5bBCG4ajV7R6vAKz4czA9",
      "EakiCSw1rfmL5DFTPNmSJZEEAEGtTp3DN12wVPJVsURS",
      "AEQ8bZRuAxAp8DV9VZnTrSudGPdNyzY2HXjPBCGy8igf",
      "DSL6bvb6j1v6SnvKjqc6fJWdsRjZ85YboH8FkzonUPiT",
      "419sTmWKAXb5526naQ93xJZL4YAYtpVkbLmzMb6k5X9m",
      "GydWCS1GwExoDNuEiW6fBLYr7cs4vwdLpk1kzDeKHq6A",
      "G8xVDYow1YcSb4cuAHwcpYSEKxFpYwC9GqYChMvbCWn5",
      "9E4F53GSXMPqwuPWEVoUQe9B1z4A8v9Y6tAQdKK779km",
      "5XtHBDxXCudA38FJnoWm1BVG8aV67AiQKnPuwYbWZCb3",
      "8Sp3v5vtYtkM9Z2K2B7PuZbWmWQE9bfiUFCvkmsdauGj",
      "8XTUXeLiHPbMNXedWQh5xHQtq4xUHU3pZZGqRQzC2eyj",
      "ftqJXjSXrWQXmumNVVaRiNB7TZuCy4GCvz9V4GJGhAv",
      "GMAYWvbBmssCr55m9bcq8cKzfczSKKxidtVrukBM1KFN",
      "3nFprwUuqGH9BpvJMQeCb5AwHdaXuxKin1WSxWc9PTkY",
      "HfYNA96cGebFGgAhGUbxvRJYyLFchQJZpJTQMXztE6gZ",
      "EPbo8xRWARg2znJAqevKnQMskxnemmCdimPiVFhr8eLd",
      "4pygr1SPEe5KbU1R8XgMmYaW7YfTH818wd113mF6bhsP",
      "52gwahUytUXv7wfKs4j6YeKeepc38sYsUi4jp4z4jVym",
      "Hi3Q1ZQbD2zztq6ajm5yUKfFccxmj3yZn79GUjhFvPSW",
      "G1yK5iwPQKNXnqU4Drg83et3gKhRW5CogqiekKEYDcrt",
      "Hf8XcEAVMCiWbu376rGS48FhwH5NgteivfsTsvX1XpbA",
      "3FAskwxrbqiX2KGEnFPuD3z89aubJvvdxZTKHCrMFjxQ",
      "GgahaaNBaHRnyUtvEu3k7N5BnW3dvhVCXyxMP6uijdhh",
      "7R9waVeAKuHKNQY5uTYBp6zNLNo6wSDvj9XfQCyRWmDF",
      "E4AoFDANgDFL83gTS6A7kjWbLmqWcPr6DqEgMG7cqU18",
      "AEkuiLFdudYmUwZ9dSa64rakqUgJZf6pKFFwwm6CZFQz",
      "3QzGZvvTQbcUdhd5BL9ofEK3GdzbmqUnYA1pYTAdVY44",
      "EjpGvdZETt3SuZpcuwKvZS4jgWCockDHzFQLoeYNW4R",
      "C85c1uMAiHKDgcqxF6EaiCGQyWgQEYATbpo8M7XEnx3R",
      "8V5y1CSC1gCGD1jai3ns5FJNW7tAzf7BGd4iwmBv7V44",
      "CJ9udTDT61ckSHMd6YNpjeNdsN2fGwmJ6Ry6YERXmGa7",
      "7eboeRCeeBCFwtzPtB4vKPnaYMPL52BjfiEpqSRWfkgx",
      "E3JJCTMouTys5BSwFyHTV3Ht55mYWfNUAverrNaVo4jE",
      "9PLHPwnHyA5jf6GPGRjJt7HNd93rw4gWTBi7LBNL4Wwt",
      "2YM2FQ4HfMiV3LFkiwop2xFznbPVEHbhahVvcrhfZtXq",
      "3oTzYXjwdr684FUzaJEVVuXBztysNgR8M8iV9QykaM9C",
      "J6bgGpwDMqKFrde2mpdS6dasRyn9WFV6jKgWAkHSN91q",
      "4wtQpa1BVgAt9CA4FUuHZHCYGBYtvudPqa1sAddfAPii",
      "DaSXwzkAU2WfH39zxMfuXpExsVfKk6JzeYbdW9RLiXr4",
      "6BtXEZE6GcxtEtSLAHXkE3mkcTG1u8WuoQxZG7R8BR5X",
      "39Z9VaCAeqoWajHyku29argf7zmVqs2vVJM8zYe7YLXy",
      "7focbpSdsNNE4x9h7eyXSkvXE6dtxsoVyZMpTpuThLoH",
      "CBdnTL6C4A7nsacxCP3VL3TqUokEraFy49ckQ196KU46",
      "CfvbDC8dxGeLXzYhDpNpCF2Ar9Q5LKs8QrfcMYAV59Lt",
      "GFseSi5squ8GRRkj6RknbGj9Hyz82HxKkcn8NKW1e5CF",
      "FuTHJNKaPTneEYRkjKAC3MkSttvAC7NtBeb2uNGS8mg3",
      "5hhPGEFCZM2HL6DNKs8KvUZAH3wC47rvMXBGftw9CCA5")
      .map(s => PublicKey25519Proposition(PublicKey @@ Base58.decode(s).get))
      .ensuring(_.length == GenesisAccountsNum)

    val genesisAccount = PrivateKey25519Companion.generateKeys("genesis".getBytes)
    val genesisAccountPriv = genesisAccount._1
    val powGenesis = PowBlock(minerSettings.GenesisParentId, minerSettings.GenesisParentId, 1481110008516L, 38,
      0, Array.fill(32)(0: Byte), genesisAccount._2, Seq())


    val genesisTxs = Seq(SimpleBoxTx(
      IndexedSeq(genesisAccountPriv -> Nonce @@ 0L),
      icoMembers.map(_ -> GenesisBalance),
      0L,
      0L))
      

    log.debug(s"Initialize state with transaction ${genesisTxs.headOption} with boxes ${genesisTxs.headOption.map(_.newBoxes)}")

    val genesisBox = PublicKey25519NoncedBox(genesisAccountPriv.publicImage, Nonce @@ 0L, GenesisBalance)
    val attachment = "genesis attachment".getBytes
    val posGenesis = PosBlock.create(powGenesis.id, 0, genesisTxs, genesisBox, attachment, genesisAccountPriv)

    var history = HybridHistory.readOrGenerate(settings, minerSettings, timeProvider)
    history = history.append(powGenesis).get._1
    history = history.append(posGenesis).get._1

    val gs = HBoxStoredState.genesisState(settings, Seq(posGenesis, powGenesis))
    val gw = HWallet.genesisWallet(settings, Seq(posGenesis, powGenesis))
      .ensuring(_.boxes().map(_.box.value.toLong).sum >= GenesisBalance  || !Base58.encode(settings.wallet.seed.arr).startsWith("genesis"))
      .ensuring(_.boxes().forall(b => gs.closedBox(b.box.id).isDefined))

    (history, gs, gw, SimpleBoxTransactionMemPool.emptyPool)
  }
}

object HybridNodeViewHolderRef {
  def props(settings: ScorexSettings,
            minerSettings: HybridMiningSettings,
            timeProvider: NetworkTimeProvider): Props =
    Props(new HybridNodeViewHolder(settings, minerSettings, timeProvider))

  def apply(settings: ScorexSettings,
            minerSettings: HybridMiningSettings,
            timeProvider: NetworkTimeProvider)
           (implicit system: ActorSystem): ActorRef =
    system.actorOf(props(settings, minerSettings, timeProvider))

  def apply(name: String,
            settings: ScorexSettings,
            minerSettings: HybridMiningSettings,
            timeProvider: NetworkTimeProvider)
           (implicit system: ActorSystem): ActorRef =
    system.actorOf(props(settings, minerSettings, timeProvider), name)
}
