package examples.hybrid.settings

import com.typesafe.config.Config
import net.ceedubs.ficus.Ficus._
import net.ceedubs.ficus.readers.ArbitraryTypeReader._
import net.ceedubs.ficus.readers.ValueReader
import scorex.core.ModifierId
import scorex.core.settings.ScorexSettings.readConfigFromPath
import scorex.core.settings._
import scorex.core.utils.ScorexLogging

import scala.concurrent.duration._

case class HybridSettings(mining: HybridMiningSettings,
                          scorexSettings: ScorexSettings,
                          treasurySettings: TreasurySettings)

case class HybridMiningSettings(offlineGeneration: Boolean,
                                targetBlockDelay: FiniteDuration,
                                blockGenerationDelay: FiniteDuration,
                                posAttachmentSize: Int,
                                rParamX10: Int,
                                initialDifficulty: BigInt) {
  lazy val MaxTarget = BigInt(1, Array.fill(32)(Byte.MinValue))
  lazy val GenesisParentId = ModifierId @@ Array.fill(32)(1: Byte)
}

case class TreasurySettings(isVoter: Boolean,
                            isExpert: Boolean,
                            isCommittee: Boolean,
                            automaticBallotGeneration: Boolean)

object HybridSettings extends ScorexLogging with SettingsReaders {
  def read(userConfigPath: Option[String]): HybridSettings = {
    fromConfig(readConfigFromPath(userConfigPath, "scorex"))
  }

  implicit val networkSettingsValueReader: ValueReader[HybridSettings] =
    (cfg: Config, path: String) => fromConfig(cfg.getConfig(path))

  private def fromConfig(config: Config): HybridSettings = {
    log.info(config.toString)
    val miningSettings = config.as[HybridMiningSettings]("scorex.miner")
    val scorexSettings = config.as[ScorexSettings]("scorex")
    var treasurySettings = config.as[TreasurySettings]("scorex.treasury")
    if (treasurySettings.isVoter && treasurySettings.isExpert)
      treasurySettings = treasurySettings.copy(isVoter = false) // don't allow to be voter and expert simultaneously
    HybridSettings(miningSettings, scorexSettings, treasurySettings)
  }
}

