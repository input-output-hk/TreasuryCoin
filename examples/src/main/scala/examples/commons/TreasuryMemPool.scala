package examples.commons

import io.iohk.iodb.ByteArrayWrapper
import scorex.core.ModifierId
import scorex.core.transaction.MemoryPool
import scorex.core.utils.ScorexLogging

import scala.collection.concurrent.TrieMap
import scala.util.{Success, Try}


case class TreasuryMemPool(unconfirmed: TrieMap[ByteArrayWrapper, SimpleBoxTransaction])
  extends MemoryPool[SimpleBoxTransaction, TreasuryMemPool] with ScorexLogging {
  override type NVCT = TreasuryMemPool

  private def key(id: Array[Byte]): ByteArrayWrapper = ByteArrayWrapper(id)

  //getters
  override def getById(id: ModifierId): Option[SimpleBoxTransaction] =
  unconfirmed.get(key(id))

  override def contains(id: ModifierId): Boolean = unconfirmed.contains(key(id))

  override def getAll(ids: Seq[ModifierId]): Seq[SimpleBoxTransaction] = ids.flatMap(getById)

  //modifiers
  override def put(tx: SimpleBoxTransaction): Try[TreasuryMemPool] = Success {
    unconfirmed.put(key(tx.id), tx)
    this
  }

  //todo
  override def put(txs: Iterable[SimpleBoxTransaction]): Try[TreasuryMemPool] = Success(putWithoutCheck(txs))

  override def putWithoutCheck(txs: Iterable[SimpleBoxTransaction]): TreasuryMemPool = {
    txs.foreach(tx => unconfirmed.put(key(tx.id), tx))
    this
  }

  override def remove(tx: SimpleBoxTransaction): TreasuryMemPool = {
    unconfirmed.remove(key(tx.id))
    this
  }

  override def take(limit: Int): Iterable[SimpleBoxTransaction] =
    unconfirmed.values.toSeq.sortBy(-_.fee).take(limit)

  override def filter(condition: (SimpleBoxTransaction) => Boolean): TreasuryMemPool = {
    unconfirmed.retain { (k, v) =>
      condition(v)
    }
    this
  }

  override def size: Int = unconfirmed.size
}


object TreasuryMemPool {
  lazy val emptyPool: TreasuryMemPool = TreasuryMemPool(TrieMap())
}