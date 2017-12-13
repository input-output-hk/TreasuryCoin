package treasury.state

import examples.hybrid.state.HBoxStoredState
import io.iohk.iodb.LSMStore
import scorex.core.VersionTag

import scala.util.Try

//case class TreasuryState (s: LSMStore, v: VersionTag) extends HBoxStoredState(s, v) {
//
//  override def validate(tx: BTX): Try[Unit] = {
//
//  }
//}
