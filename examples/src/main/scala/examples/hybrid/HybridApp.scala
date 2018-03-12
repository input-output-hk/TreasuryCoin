package examples.hybrid

import java.io.File

import akka.actor.{ActorRef, Props}
import examples.commons.{SimpleBoxTransaction, SimpleBoxTransactionMemPool}
import examples.hybrid.api.http.{DebugApiRoute, StatsApiRoute, TreasuryApiRoute, WalletApiRoute}
import examples.hybrid.blocks.HybridBlock
import examples.hybrid.history.{HybridHistory, HybridSyncInfo, HybridSyncInfoMessageSpec}
import examples.hybrid.mining.{PosForgerRef, PowMinerRef}
import examples.hybrid.settings.HybridSettings
import examples.hybrid.transaction.TreasuryTxForgerRef
import examples.hybrid.wallet.TreasuryTransactionGenerator
import scorex.core.api.http.{ApiRoute, NodeViewApiRoute, PeersApiRoute, UtilsApiRoute}
import scorex.core.app.Application
import scorex.core.network.NodeViewSynchronizerRef
import scorex.core.network.message.MessageSpec
import scorex.core.settings.ScorexSettings
import scorex.core.transaction.box.proposition.PublicKey25519Proposition

import scala.concurrent.duration._
import scala.io.Source
import scala.language.postfixOps

class HybridApp(val settingsFilename: String) extends Application {

  override type P = PublicKey25519Proposition
  override type TX = SimpleBoxTransaction
  override type PMOD = HybridBlock
  override type NVHT = HybridNodeViewHolder

  private val hybridSettings = HybridSettings.read(Some(settingsFilename))
  implicit override lazy val settings: ScorexSettings = HybridSettings.read(Some(settingsFilename)).scorexSettings

  log.debug(s"Starting application with settings \n$settings")

  override protected lazy val additionalMessageSpecs: Seq[MessageSpec[_]] = Seq(HybridSyncInfoMessageSpec)

  override val nodeViewHolderRef: ActorRef = HybridNodeViewHolderRef(settings, hybridSettings.mining, timeProvider)

  override val apiRoutes: Seq[ApiRoute] = Seq(
    DebugApiRoute(settings.restApi, nodeViewHolderRef),
    WalletApiRoute(settings.restApi, nodeViewHolderRef),
    StatsApiRoute(settings.restApi, nodeViewHolderRef),
    UtilsApiRoute(settings.restApi),
    NodeViewApiRoute[P, TX](settings.restApi, nodeViewHolderRef),
    PeersApiRoute(peerManagerRef, networkControllerRef, settings.restApi),
    TreasuryApiRoute(settings.restApi, nodeViewHolderRef),
  )

  override val swaggerConfig: String = Source.fromResource("api/testApi.yaml").getLines.mkString("\n")

  val miner: ActorRef = PowMinerRef(nodeViewHolderRef, hybridSettings.mining)
  val forger: ActorRef = PosForgerRef(hybridSettings, nodeViewHolderRef)
  val treasuryTxsForger: ActorRef = TreasuryTxForgerRef(nodeViewHolderRef, hybridSettings.treasurySettings)

  override val localInterface: ActorRef = HLocalInterfaceRef(nodeViewHolderRef, miner, forger, treasuryTxsForger, hybridSettings.mining)

  override val nodeViewSynchronizer: ActorRef =
    actorSystem.actorOf(NodeViewSynchronizerRef.props[P, TX, HybridSyncInfo, HybridSyncInfoMessageSpec.type,
                                                      PMOD, HybridHistory, SimpleBoxTransactionMemPool]
                                                     (networkControllerRef, nodeViewHolderRef, localInterface,
                                                      HybridSyncInfoMessageSpec, settings.network, timeProvider))

  //touching lazy vals
  miner
  localInterface
  nodeViewSynchronizer

//  if (settings.network.nodeName.startsWith("generatorNode")) {
//    log.info("Starting transactions generation")
//    val generator: ActorRef = SimpleBoxTransactionGeneratorRef(nodeViewHolderRef)
//    generator ! StartGeneration(10 seconds)
//  }

  if (settings.network.nodeName.startsWith("node1")) {
    log.info("Starting treasury transactions generation")
    val generator: ActorRef = actorSystem.actorOf(Props(new TreasuryTransactionGenerator(nodeViewHolderRef)))
    generator ! TreasuryTransactionGenerator.StartGeneration(15 seconds)
  }
}

object HybridApp extends App {
  val settingsFilename = args.headOption.getOrElse("settings.conf")
  new HybridApp(settingsFilename).run()
}
