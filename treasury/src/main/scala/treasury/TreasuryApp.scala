package treasury

import examples.hybrid.HybridApp

object TreasuryApp extends App {
  val settingsFilename = args.headOption.getOrElse("settings.conf")
  new HybridApp(settingsFilename).run()
}
