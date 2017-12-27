package examples.hybrid

import examples.commons.{SimpleBoxTransaction, SimpleBoxTx, SimpleBoxTxCompanion, TreasuryMemPool}
import examples.curvepos.{Nonce, Value}
import examples.curvepos.transaction.PublicKey25519NoncedBox
import examples.hybrid.HybridNodeViewHolder.{CurrentViewWithTreasuryState, GetDataFromCurrentViewWithTreasuryState}
import examples.hybrid.blocks._
import examples.hybrid.history.{HybridHistory, HybridSyncInfo}
import examples.hybrid.mining.HybridMiningSettings
import examples.hybrid.state.{HBoxStoredState, TreasuryState}
import examples.hybrid.wallet.HWallet
import scorex.core.NodeViewHolder._
import scorex.core.serialization.Serializer
import scorex.core.settings.ScorexSettings
import scorex.core.transaction.Transaction
import scorex.core.transaction.box.proposition.PublicKey25519Proposition
import scorex.core.transaction.state.PrivateKey25519Companion
import scorex.core.{ModifierTypeId, NodeViewHolder, NodeViewModifier, VersionTag}
import scorex.crypto.encode.Base58
import scorex.crypto.signatures.PublicKey

import scala.util.{Failure, Success}


class HybridNodeViewHolder(settings: ScorexSettings, minerSettings: HybridMiningSettings) extends NodeViewHolder[PublicKey25519Proposition,
  SimpleBoxTransaction,
  HybridBlock] {
  override val networkChunkSize: Int = settings.network.networkChunkSize

  override type SI = HybridSyncInfo

  override type HIS = HybridHistory
  override type MS = HBoxStoredState
  override type VL = HWallet
  override type MP = TreasuryMemPool

  private var treasuryState = TreasuryState.generate(history).get

  override val modifierSerializers: Map[ModifierTypeId, Serializer[_ <: NodeViewModifier]] =
    Map(PosBlock.ModifierTypeId -> PosBlockCompanion,
      PowBlock.ModifierTypeId -> PowBlockCompanion,
      Transaction.ModifierTypeId -> SimpleBoxTxCompanion)

  override def preRestart(reason: Throwable, message: Option[Any]): Unit = {
    super.preRestart(reason, message)
    reason.printStackTrace()
    System.exit(100) // this actor shouldn't be restarted at all so kill the whole app if that happened
  }

  /**
    * Hard-coded initial view all the honest nodes in a network are making progress from.
    */
  override protected def genesisState: (HIS, MS, VL, MP) = {
    val GenesisAccountsNum = 50
    val GenesisBalance = Value @@ 100000000L

    //propositions with wallet seed genesisoo, genesiso1, ..., genesis48, genesis49
    val icoMembers: IndexedSeq[PublicKey25519Proposition] = IndexedSeq("6sYyiTguyQ455w2dGEaNbrwkAWAEYV1Zk6FtZMknWDKQ", "7BDhJv6Wh2MekgJLvQ98ot9xiw5x3N4b3KipURdrW8Ge", "Ei8oY3eg5vM26QUBhyFiAdPN1C23RJEV9irrykNmSAFV", "8LNhm5QagL88sWggvJKGDiZ5bBCG4ajV7R6vAKz4czA9", "EakiCSw1rfmL5DFTPNmSJZEEAEGtTp3DN12wVPJVsURS", "AEQ8bZRuAxAp8DV9VZnTrSudGPdNyzY2HXjPBCGy8igf", "DSL6bvb6j1v6SnvKjqc6fJWdsRjZ85YboH8FkzonUPiT", "419sTmWKAXb5526naQ93xJZL4YAYtpVkbLmzMb6k5X9m", "GydWCS1GwExoDNuEiW6fBLYr7cs4vwdLpk1kzDeKHq6A", "G8xVDYow1YcSb4cuAHwcpYSEKxFpYwC9GqYChMvbCWn5", "9E4F53GSXMPqwuPWEVoUQe9B1z4A8v9Y6tAQdKK779km", "5XtHBDxXCudA38FJnoWm1BVG8aV67AiQKnPuwYbWZCb3", "8Sp3v5vtYtkM9Z2K2B7PuZbWmWQE9bfiUFCvkmsdauGj", "8XTUXeLiHPbMNXedWQh5xHQtq4xUHU3pZZGqRQzC2eyj", "ftqJXjSXrWQXmumNVVaRiNB7TZuCy4GCvz9V4GJGhAv", "GMAYWvbBmssCr55m9bcq8cKzfczSKKxidtVrukBM1KFN", "3nFprwUuqGH9BpvJMQeCb5AwHdaXuxKin1WSxWc9PTkY", "HfYNA96cGebFGgAhGUbxvRJYyLFchQJZpJTQMXztE6gZ", "EPbo8xRWARg2znJAqevKnQMskxnemmCdimPiVFhr8eLd", "4pygr1SPEe5KbU1R8XgMmYaW7YfTH818wd113mF6bhsP", "52gwahUytUXv7wfKs4j6YeKeepc38sYsUi4jp4z4jVym", "Hi3Q1ZQbD2zztq6ajm5yUKfFccxmj3yZn79GUjhFvPSW", "G1yK5iwPQKNXnqU4Drg83et3gKhRW5CogqiekKEYDcrt", "Hf8XcEAVMCiWbu376rGS48FhwH5NgteivfsTsvX1XpbA", "3FAskwxrbqiX2KGEnFPuD3z89aubJvvdxZTKHCrMFjxQ", "GgahaaNBaHRnyUtvEu3k7N5BnW3dvhVCXyxMP6uijdhh", "7R9waVeAKuHKNQY5uTYBp6zNLNo6wSDvj9XfQCyRWmDF", "E4AoFDANgDFL83gTS6A7kjWbLmqWcPr6DqEgMG7cqU18", "AEkuiLFdudYmUwZ9dSa64rakqUgJZf6pKFFwwm6CZFQz", "3QzGZvvTQbcUdhd5BL9ofEK3GdzbmqUnYA1pYTAdVY44", "EjpGvdZETt3SuZpcuwKvZS4jgWCockDHzFQLoeYNW4R", "C85c1uMAiHKDgcqxF6EaiCGQyWgQEYATbpo8M7XEnx3R", "8V5y1CSC1gCGD1jai3ns5FJNW7tAzf7BGd4iwmBv7V44", "CJ9udTDT61ckSHMd6YNpjeNdsN2fGwmJ6Ry6YERXmGa7", "7eboeRCeeBCFwtzPtB4vKPnaYMPL52BjfiEpqSRWfkgx", "E3JJCTMouTys5BSwFyHTV3Ht55mYWfNUAverrNaVo4jE", "9PLHPwnHyA5jf6GPGRjJt7HNd93rw4gWTBi7LBNL4Wwt", "2YM2FQ4HfMiV3LFkiwop2xFznbPVEHbhahVvcrhfZtXq", "3oTzYXjwdr684FUzaJEVVuXBztysNgR8M8iV9QykaM9C", "J6bgGpwDMqKFrde2mpdS6dasRyn9WFV6jKgWAkHSN91q", "4wtQpa1BVgAt9CA4FUuHZHCYGBYtvudPqa1sAddfAPii", "DaSXwzkAU2WfH39zxMfuXpExsVfKk6JzeYbdW9RLiXr4", "6BtXEZE6GcxtEtSLAHXkE3mkcTG1u8WuoQxZG7R8BR5X", "39Z9VaCAeqoWajHyku29argf7zmVqs2vVJM8zYe7YLXy", "7focbpSdsNNE4x9h7eyXSkvXE6dtxsoVyZMpTpuThLoH", "CBdnTL6C4A7nsacxCP3VL3TqUokEraFy49ckQ196KU46", "CfvbDC8dxGeLXzYhDpNpCF2Ar9Q5LKs8QrfcMYAV59Lt", "GFseSi5squ8GRRkj6RknbGj9Hyz82HxKkcn8NKW1e5CF", "FuTHJNKaPTneEYRkjKAC3MkSttvAC7NtBeb2uNGS8mg3", "5hhPGEFCZM2HL6DNKs8KvUZAH3wC47rvMXBGftw9CCA5").map(s => PublicKey25519Proposition(PublicKey @@ Base58.decode(s).get))

    val genesisAccount = PrivateKey25519Companion.generateKeys("genesis".getBytes)
    val genesisAccountPriv = genesisAccount._1
    val powGenesis = PowBlock(minerSettings.GenesisParentId, minerSettings.GenesisParentId, 1481110008516L, 38,
      0, Array.fill(32)(0: Byte), genesisAccount._2, Seq())


    val genesisTxs = Seq(SimpleBoxTx(
      IndexedSeq(genesisAccountPriv -> Nonce @@ 0L),
      icoMembers.map(_ -> GenesisBalance),
      0L,
      0L))
    log.debug(s"Initialize state with transaction ${genesisTxs.head} with boxes ${genesisTxs.head.newBoxes}")
    assert(icoMembers.length == GenesisAccountsNum)
    assert(Base58.encode(genesisTxs.head.id) == "EKuWxCuUAg9XgVWKxsnehP9FLsF3zPSyn9yczqeBHD8S", Base58.encode(genesisTxs.head.id))

    val genesisBox = PublicKey25519NoncedBox(genesisAccountPriv.publicImage, Nonce @@ 0L, GenesisBalance)
    val attachment = "genesis attachment".getBytes
    val posGenesis = PosBlock.create(powGenesis.id, 0, genesisTxs, genesisBox, attachment, genesisAccountPriv)

    var history = HybridHistory.readOrGenerate(settings, minerSettings)
    history = history.append(powGenesis).get._1
    history = history.append(posGenesis).get._1

    val gs = HBoxStoredState.genesisState(settings, Seq(posGenesis, powGenesis))
    val gw = HWallet.genesisWallet(settings, Seq(posGenesis, powGenesis))
    assert(!Base58.encode(settings.wallet.seed.arr).startsWith("genesis") || gw.boxes().map(_.box.value.toLong).sum >= GenesisBalance)

    assert(gw.boxes().forall(b => gs.closedBox(b.box.id).isDefined))

    (history, gs, gw, TreasuryMemPool.emptyPool)
  }

  /**
    * Restore a local view during a node startup. If no any stored view found
    * (e.g. if it is a first launch of a node) None is to be returned
    */
  override def restoreState(): Option[(HIS, MS, VL, MP)] = {
    if (HWallet.exists(settings)) {
      Some((
        HybridHistory.readOrGenerate(settings, minerSettings),
        HBoxStoredState.readOrGenerate(settings),
        HWallet.readOrGenerate(settings, 1),
        TreasuryMemPool.emptyPool))
    } else None
  }

  override def pmodModify(pmod: HybridBlock): Unit = {

    treasuryState.validate(pmod, history) match {
      case Failure(e) =>
        log.warn(s"Persistent modifier (id: ${pmod.encodedId}, contents: $pmod) is not valid against treasury state", e)
        notifySubscribers(EventType.SemanticallyFailedPersistentModifier, SemanticallyFailedModification(pmod, e))
        return
      case _ =>
    }

    if (!history().contains(pmod.id)) {
      notifySubscribers(EventType.StartingPersistentModifierApplication, StartingPersistentModifierApplication(pmod))

      log.info(s"Apply modifier ${pmod.encodedId} of type ${pmod.modifierTypeId} to nodeViewHolder")

      history().append(pmod) match {
        case Success((historyBeforeStUpdate, progressInfo)) =>
          log.debug(s"Going to apply modifications to the state: $progressInfo")
          notifySubscribers(EventType.SuccessfulSyntacticallyValidModifier, SyntacticallySuccessfulModifier(pmod))
          notifySubscribers(EventType.OpenSurfaceChanged, NewOpenSurface(historyBeforeStUpdate.openSurfaceIds()))

          if (progressInfo.toApply.nonEmpty) {
            val (newHistory, newStateTry) = updateState(historyBeforeStUpdate, minimalState(), progressInfo)
            newStateTry match {
              case Success(newMinState) =>
                val newMemPool = updateMemPool(progressInfo, memoryPool(), newMinState)

                //we consider that vault always able to perform a rollback needed
                val newVault = if (progressInfo.chainSwitchingNeeded) {
                  vault().rollback(VersionTag @@ progressInfo.branchPoint.get).get.scanPersistent(progressInfo.toApply)
                } else {
                  vault().scanPersistent(progressInfo.toApply)
                }

                log.info(s"Persistent modifier ${pmod.encodedId} applied successfully")
                nodeView = (newHistory, newMinState, newVault, newMemPool)

                /* if everything is ok we can update treasury state */
                treasuryState = if (progressInfo.chainSwitchingNeeded) {
                  TreasuryState.generate(newHistory).get // in case of rollback regenerate it entirely
                } else {
                  treasuryState.apply(pmod).get
                }

              case Failure(e) =>
                log.warn(s"Can`t apply persistent modifier (id: ${pmod.encodedId}, contents: $pmod) to minimal state", e)
                nodeView = (newHistory, minimalState(), vault(), memoryPool())
                notifySubscribers(EventType.SemanticallyFailedPersistentModifier, SemanticallyFailedModification(pmod, e))
            }
          } else {
            requestDownloads(progressInfo)
            nodeView = (historyBeforeStUpdate, minimalState(), vault(), memoryPool())
          }
        case Failure(e) =>
          log.warn(s"Can`t apply persistent modifier (id: ${pmod.encodedId}, contents: $pmod) to history", e)
          notifySubscribers(EventType.SyntacticallyFailedPersistentModifier, SyntacticallyFailedModification(pmod, e))
      }
    } else {
      log.warn(s"Trying to apply modifier ${pmod.encodedId} that's already in history")
    }
  }

  override def getCurrentInfo: Receive = {
    super.getCurrentInfo orElse {
      case GetDataFromCurrentViewWithTreasuryState(f) =>
        sender() ! f(CurrentViewWithTreasuryState(history(), minimalState(), vault(), memoryPool(), treasuryState))
    }
  }
}

object HybridNodeViewHolder {

  case class GetDataFromCurrentViewWithTreasuryState[HIS, MS, VL, MP, A](f: CurrentViewWithTreasuryState[HIS, MS, VL, MP] => A)

  case class CurrentViewWithTreasuryState[HIS, MS, VL, MP](history: HIS, state: MS, vault: VL, pool: MP, trState: TreasuryState)
}