from armoryengine import *
from twisted.internet.protocol import Protocol, ClientFactory
from twisted.internet.defer import Deferred




##########################################################################
##########################################################################
#
#
# SATOSHI-DICE DOUBLE-SPEND DETECTION BRANCH CODE
# Want to try to detect double-spends made to these address.
if USE_TESTNET:
   SDADDRSET = set([
   '', \
   '' ])
else:
   SDADDRSET = set([
   '1dice9wVtrKZTBbAZqz1XiTmboYyvpD3t', \
   '1diceDCd27Cc22HV3qPNZKwGnZ8QwhLTc', \
   '1dicegEArYHgbwQZhvr5G9Ah2s7SFuW1y', \
   '1dicec9k7KpmQaA8Uc8aCCxfWnwEWzpXE', \
   '1dice9wcMu5hLF4g81u8nioL5mmSHTApw', \
   '1dice97ECuByXAvqXpaYzSaQuPVvrtmz6', \
   '1dice8EMZmqKvrGE4Qc9bUFf9PX3xaYDp', \
   '1dice7W2AicHosf5EL3GFDUVga7TgtPFn', \
   '1dice7fUkz5h4z2wPc1wLMPWgB5mDwKDx', \
   '1dice7EYzJag7SxkdKXLr8Jn14WUb3Cf1', \
   '1dice6YgEVBf88erBFra9BHf6ZMoyvG88', \
   '1dice6wBxymYi3t94heUAG6MpG5eceLG1', \
   '1dice6GV5Rz2iaifPvX7RMjfhaNPC8SXH', \
   '1dice6gJgPDYz8PLQyJb8cgPBnmWqCSuF', \
   '1dice6DPtUMBpWgv8i4pG8HMjXv9qDJWN', \
   '1dice61SNWEKWdA8LN6G44ewsiQfuCvge', \
   '1dice5wwEZT2u6ESAdUGG6MHgCpbQqZiy', \
   '1dice4J1mFEvVuFqD14HzdViHFGi9h4Pp', \
   '1dice3jkpTvevsohA4Np1yP4uKzG1SRLv', \
   '1dice37EemX64oHssTreXEFT3DXtZxVXK', \
   '1dice2zdoxQHpGRNaAWiqbK82FQhr4fb5', \
   '1dice2xkjAAiphomEJA5NoowpuJ18HT1s', \
   '1dice2WmRTLf1dEk4HH3Xs8LDuXzaHEQU', \
   '1dice2vQoUkQwDMbfDACM1xz6svEXdhYb', \
   '1dice2pxmRZrtqBVzixvWnxsMa7wN2GCK', \
   '1dice1Qf4Br5EYjj9rnHWqgMVYnQWehYG', \
   '1dice1e6pdhLzzWQq7yMidf6j8eAg7pkY' ])
SDHASH160SET = set([addrStr_to_hash160(a) for a in SDADDRSET])

#testTx = PyTx().unserialize(hex_to_binary('0100000001014dcf77a47d86a5e7a0378447a9fee11067fe313daa65c1fa76468c1875728a000000008a4730440220738355af6770c034b4b913a64d65aab9f22b1ef9006fdc64935be18447a4e08c02201fce7e0beecc3b30db04bd939e62a49e15060b401d412faefd350c9549befb2c01410455c4a969d0d52aa6d92f866aed9acf720cb0f8a0222057788413ad00c9b87f3594ada0c118b17df0c757450a3db64ea03de41a6acdc73d7fe95be51c1466f2dfffffffff0140420f00000000001976a91406f1b66e25393fabd2b23a237e4bdfd4c2c35fac88ac00000000'))
#conflictTx = PyTx().unserialize(hex_to_binary('0100000001014dcf77a47d86a5e7a0378447a9fee11067fe313daa65c1fa76468c1875728a000000008a47304402206bd7ea583fa5cf688fc735606f8e812992ba785fb3723fe72017c17283a209a302201ae91890d69d458d6317848c5b1bf93d630f8f073feb5ee7192bd75a698a519901410455c4a969d0d52aa6d92f866aed9acf720cb0f8a0222057788413ad00c9b87f3594ada0c118b17df0c757450a3db64ea03de41a6acdc73d7fe95be51c1466f2dfffffffff0140420f00000000001976a91406f1b66e25393fabd2b23a237e4bdfd4c2c35fac88ac00000000'))
#testTxHash = testTx.getHash()
#conflictHash = conflictTx.getHash()
#print 'Test Tx Hash:', binary_to_hex(testTxHash, endOut=BIGENDIAN)
#print 'Conflict Tx Hash:', binary_to_hex(conflictHash, endOut=BIGENDIAN)
#
#
##########################################################################
##########################################################################

b2h = lambda x: binary_to_hex(x, BIGENDIAN)

zcConfTxMap = {}
zcSDBets = set([])
mapOutPointAffectsBet  = {}
mapOutPointSpentInTxID = {}
mapOutPointAffectsVal  = {}

def newTxFunc(pytxObj):
   totalVal = 0
   thisTxHash = pytxObj.getHash()

   #if thisTxHash==conflictHash:
      #print 'IGNORING CONFLICT'
      #return

   thisTxSDBets = set([])
   zcConfTxMap[thisTxHash] = pytxObj.serialize()
   for output in pytxObj.outputs:
      # Check if any outputs are bets to SD
      try:
         if TxOutScriptExtractAddr160(output.binScript) in SDHASH160SET:
            thisTxSDBets.add(thisTxHash)
            totalVal += output.value
      except:
         print 'Skipping error in reading tx outputs'

   #if len(thisTxSDBets)>0:
      #print 'Bet:', ' '*13, b2h(thisTxHash), coin2str(totalVal)

   while len(thisTxSDBets)>0:
      # If we get here, we are adding at least one zero-conf tx to the map
      # If it depends on other zero-conf tx, this loop will repeat and add 
      # those too
      # "ItsOwn" here refers to the hash of the particular tx we just popped
      # as opposed to the SD bet that is ultimately affected by this one
      itsOwnTxHash = thisTxSDBets.pop()
      affectsBetTxHash = thisTxHash
      if zcConfTxMap.has_key(itsOwnTxHash):
         zcSDBets.add(itsOwnTxHash)
         thisTx = PyTx().unserialize(zcConfTxMap[itsOwnTxHash])
         for inp in thisTx.inputs:
            op = inp.outpoint
            mapOutPointSpentInTxID[op.serialize()] = itsOwnTxHash
            mapOutPointAffectsBet[op.serialize()]  = affectsBetTxHash
            mapOutPointAffectsVal[op.serialize()]  = totalVal
            if zcConfTxMap.has_key(op.txHash):
               thisTxSDBets.add(op.txHash)
         

def newBlockFunc(pyHeader, pyTxList):
   
   # First clear out all SD-relevant bets that were just cemented in the blockchain
   skipSet = set([])
   for tx in pyTxList:
      txHash = tx.getHash()
      if txHash in zcSDBets:
         zcSDBets.remove(txHash)
         skipSet.add(txHash)
         for inp in tx.inputs:
            opstr = inp.outpoint.serialize()
            del(mapOutPointSpentInTxID[opstr])
            del(mapOutPointAffectsBet[opstr])
            del(mapOutPointAffectsVal[opstr])

      if txHash in zcConfTxMap:
         skipSet.add(txHash)
         del(zcConfTxMap[txHash])

   # Next, look for tx spending outputs which an SD-bet depends on
   for tx in pyTxList:
      txHash = tx.getHash()
      if txHash in skipSet:
         continue

      # These are the surprise tx in the blockchain for which we didn't see ZC tx
      for inp in tx.inputs:
         # Search for OutPoints being spent that would invalidate an SD bet
         op = inp.outpoint
         if mapOutPointSpentInTxID.has_key(op.serialize()):
            with open('invalidated_bets.txt', 'a') as f:
               txInvalid0 = mapOutPointSpentInTxID[op.serialize()]
               txInvalid1 = mapOutPointAffectsBet[op.serialize()]
               txHexInvalid0 = b2h(txInvalid0)
               txHexInvalid1 = b2h(txInvalid1)
               betVal        = mapOutPointAffectsVal[op.serialize()]
               s = 'RightNow: %s; TxInvalid: %s; BetInvalid: %s; AmtInvalid: %s\n' % \
                     (unixTimeToFormatStr(RightNow()), txHexInvalid0, txHexInvalid1, coin2str(betVal))
               print s
               f.write(s)
               f.write('\n' + b2h(txHash) + ' : ' + binary_to_hex(tx.serialize()))
               if zcConfTxMap.has_key(txInvalid0):
                  f.write('\n' + txHexInvalid0 + ' : ' + binary_to_hex(zcConfTxMap[txInvalid0]))
               if zcConfTxMap.has_key(hex_to_binary(txHexInvalid1)):
                  f.write('\n' + txHexInvalid1 + ' : ' + binary_to_hex(zcConfTxMap[txInvalid1]))
               
            # Remove the invalidated tx
            if txHexInvalid0 in zcConfTxMap:    del(zcConfTxMap[txHexInvalid0])
            if txHexInvalid1 in zcConfTxMap:    del(zcConfTxMap[txHexInvalid1])
            if txHexInvalid0 in zcSDBets:       zcSDBets.remove(txHexInvalid0)
            if txHexInvalid1 in zcSDBets:       zcSDBets.remove(txHexInvalid1)
      




from twisted.internet import reactor
NetworkingFactory = ArmoryClientFactory( \
                             func_loseConnect=(lambda: 1), \
                             func_madeConnect=(lambda: 1), \
                             func_newTx=newTxFunc, \
                             func_newBlock=newBlockFunc)

reactor.callWhenRunning(reactor.connectTCP, '127.0.0.1', \
                        BITCOIN_PORT, NetworkingFactory)




def heartbeat(nextBeatSec=5):
   try:
      pass
      #print 'All:', len(zcConfTxMap),
      #print 'SD:',  len(zcSDBets),
      #print 'MAP:', len(mapOutPointSpentInTxID)
      
   finally:
      from twisted.internet import reactor
      reactor.callLater(nextBeatSec, heartbeat)



#def injectTx():
   #print '*'*80
   #print '*'*80
   #print 'Injecting tx to be double-spent'
   #print '*'*80
   #print '*'*80
   #newTxFunc(testTx)   


reactor.callLater(1, heartbeat)
#reactor.callLater(10, injectTx)
reactor.run()








