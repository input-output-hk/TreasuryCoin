package examples.hybrid.validation

import examples.hybrid.blocks.{HybridBlock, PosBlock, PowBlock}
import scorex.core.block.BlockValidator

import scala.util.Try

/**
  * Validates treasury transactions in a block. At least checks that
  */
class TreasuryBlockValidator extends BlockValidator[HybridBlock] {

  def validate(block: HybridBlock): Try[Unit] = Try {
    block match {
      case powBlock: PowBlock => Try(Unit)
      case posBlock: PosBlock => Try(Unit)
    }
  }
}
