package hybrid

import examples.commons.{SimpleBoxTransaction, TreasuryMemPool}
import examples.hybrid.blocks.HybridBlock
import examples.hybrid.history.{HybridHistory, HybridSyncInfo}
import examples.hybrid.state.HBoxStoredState
import scorex.core.transaction.box.proposition.PublicKey25519Proposition
import scorex.testkit.properties.NodeViewSynchronizerTests

class NodeViewSynchronizerSpec extends NodeViewSynchronizerTests[PublicKey25519Proposition,
  SimpleBoxTransaction,
  HybridBlock,
  HBoxStoredState,
  HybridSyncInfo,
  HybridHistory,
  TreasuryMemPool] with HybridGenerators {

  override lazy val memPool: TreasuryMemPool = TreasuryMemPool.emptyPool
}
