from armoryengine import * 
from time import sleep
import sys

TheBDM.setBlocking(False) 
TheBDM.setOnlineMode(True)

allLines = []
with open('invalidated_bets.txt','r') as f:
   allLines = [l.strip() for l in f.readlines() if len(l.strip())>0]
   
valid_tx = [[a.strip() for a in line.split(':')] for line in allLines[::2]]
inval_tx = [[a.strip() for a in line.split(':')] for line in [a.split('R')[0] for a in allLines[1::2]]]


print 'VALID TX'.center(64), 'INVALID TX'.center(64)
print '-'*130
for i in range(len(valid_tx)):
   print valid_tx[i][0], inval_tx[i][0]


print 'Scanning blockchain',
while not TheBDM.getBDMState()=='BlockchainReady':
   sleep(1)
   print '.',
   sys.stdout.flush()


def computeFee(rawTxHex, isValid):
   #validHashHex = valid_tx[0]
   #validRawTx   = hex_to_binary(valid_tx[1])
   #invalHashHex = inval_tx[0]
   #invalRawTx   = hex_to_binary(inval_tx[1])
   

   rawTx = hex_to_binary(rawTxHex)
   hashHex = binary_to_hex(hash256(rawTx), BIGENDIAN)
   txObj = PyTx().unserialize(rawTx)
   txObj.pprint()

   totalIn = 0
   print ('VALID TX:' if isValid else 'INVALIDATED TX:'), hashHex, len(rawTx)
   for i,txin in enumerate(txObj.inputs):
      opHash = binary_to_hex(txin.outpoint.txHash)[0:16]
      cppTx = TheBDM.getTxByHash(txin.outpoint.txHash)
      if not cppTx.isInitialized():
         print 'TX OF OUTPOINT NOT AVAILABLE', opHash
         continue
      cppTxOut = cppTx.getTxOut(txin.outpoint.txOutIndex)
      thisVal = cppTxOut.getValue()
      totalIn += thisVal
      print '\tIN: ', opHash, txin.outpoint.txOutIndex, '\t', coin2str(thisVal, maxZeros=0)

   print ''
   totalOut = 0
   for txout in txObj.outputs:
      print '\tOUT:', TxOutScriptExtractAddrStr(txout.binScript), '\t', coin2str(txout.value, maxZeros=0)
      totalOut += txout.value
      
   print '-'*80
   print '\tTOTAL FEE:', coin2str(totalIn - totalOut, maxZeros=0)


for i in range(len(valid_tx)):
   print valid_tx[i][0]
   computeFee( valid_tx[i][1], isValid=True)
   computeFee( inval_tx[i][1], isValid=False)
