////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2011-2012, Alan C. Reiner    <alan.reiner@gmail.com>        //
//  Distributed under the GNU Affero General Public License (AGPL v3)         //
//  See LICENSE or http://www.gnu.org/licenses/agpl.html                      //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////
#include "EncryptionUtils.h"
#include "integer.h"
#include "oids.h"


#define CRYPTO_DEBUG false


/////////////////////////////////////////////////////////////////////////////
// We have to explicitly re-define some of these methods...
SecureBinaryData & SecureBinaryData::append(SecureBinaryData & sbd2) 
{
   if(sbd2.getSize()==0) 
      return (*this);

   if(getSize()==0) 
      BinaryData::copyFrom(sbd2.getPtr(), sbd2.getSize());
   else
      BinaryData::append(sbd2.getRawRef());

   lockData();
   return (*this);
}


/////////////////////////////////////////////////////////////////////////////
SecureBinaryData & SecureBinaryData::append(BinaryData & bd) 
{
   if(bd.getSize()==0) 
      return (*this);

   if(getSize()==0) 
      BinaryData::copyFrom(bd.getPtr(), bd.getSize());
   else
      BinaryData::append(bd.getRef());

   lockData();
   return (*this);
}


/////////////////////////////////////////////////////////////////////////////
SecureBinaryData SecureBinaryData::operator+(SecureBinaryData & sbd2) const
{
   SecureBinaryData out(getSize() + sbd2.getSize());
   memcpy(out.getPtr(), getPtr(), getSize());
   memcpy(out.getPtr()+getSize(), sbd2.getPtr(), sbd2.getSize());
   out.lockData();
   return out;
}

/////////////////////////////////////////////////////////////////////////////
SecureBinaryData & SecureBinaryData::operator=(SecureBinaryData const & sbd2)
{ 
   copyFrom(sbd2.getPtr(), sbd2.getSize() );
   lockData(); 
   return (*this);
}

/////////////////////////////////////////////////////////////////////////////
bool SecureBinaryData::operator==(SecureBinaryData const & sbd2) const
{ 
   if(getSize() != sbd2.getSize())
      return false;
   for(unsigned int i=0; i<getSize(); i++)
      if( (*this)[i] != sbd2[i] )
         return false;
   return true;
}

/////////////////////////////////////////////////////////////////////////////
// Swap endianness of the bytes in the index range [pos1, pos2)
SecureBinaryData SecureBinaryData::copySwapEndian(size_t pos1, size_t pos2) const
{
   return SecureBinaryData(BinaryData::copySwapEndian(pos1, pos2));
}

/////////////////////////////////////////////////////////////////////////////
SecureBinaryData SecureBinaryData::GenerateRandom(uint32_t numBytes)
{
   static CryptoPP::AutoSeededRandomPool prng;
   SecureBinaryData randData(numBytes);
   prng.GenerateBlock(randData.getPtr(), numBytes);
   return randData;  
}

/////////////////////////////////////////////////////////////////////////////
KdfRomix::KdfRomix(void) : 
   hashFunctionName_( "sha512" ),
   hashOutputBytes_( 64 ),
   kdfOutputBytes_( 32 ),
   memoryReqtBytes_( 32 ),
   numIterations_( 0 )
{ 
   // Nothing to do here
}

/////////////////////////////////////////////////////////////////////////////
KdfRomix::KdfRomix(uint32_t memReqts, uint32_t numIter, SecureBinaryData salt) :
   hashFunctionName_( "sha512" ),
   hashOutputBytes_( 64 ),
   kdfOutputBytes_( 32 )
{
   usePrecomputedKdfParams(memReqts, numIter, salt);
}

/////////////////////////////////////////////////////////////////////////////
void KdfRomix::computeKdfParams(double targetComputeSec, uint32_t maxMemReqts)
{
   // Create a random salt, even though this is probably unnecessary:
   // the variation in numIter and memReqts is probably effective enough
   salt_ = SecureBinaryData().GenerateRandom(32);

   // If target compute is 0s, then this method really only generates 
   // a random salt, and sets the other params to default minimum.
   if(targetComputeSec == 0)
   {
      numIterations_ = 1;
      memoryReqtBytes_ = 1024;
      return;
   }


   // Here, we pick the largest memory reqt that allows the executing system
   // to compute the KDF is less than the target time.  A maximum can be 
   // specified, in case the target system is likely to be memory-limited
   // more than compute-speed limited
   SecureBinaryData testKey("This is an example key to test KDF iteration speed");

   // Start the search for a memory value at 1kB
   memoryReqtBytes_ = 1024;
   double approxSec = 0;
   while(approxSec <= targetComputeSec/4 && memoryReqtBytes_ < maxMemReqts)
   {
      memoryReqtBytes_ *= 2;

      sequenceCount_ = memoryReqtBytes_ / hashOutputBytes_;
      lookupTable_.resize(memoryReqtBytes_);

      TIMER_RESTART("KDF_Mem_Search");
      testKey = DeriveKey_OneIter(testKey);
      TIMER_STOP("KDF_Mem_Search");
      approxSec = TIMER_READ_SEC("KDF_Mem_Search");
   }

   // Recompute here, in case we didn't enter the search above 
   sequenceCount_ = memoryReqtBytes_ / hashOutputBytes_;
   lookupTable_.resize(memoryReqtBytes_);


   // Depending on the search above (or if a low max memory was chosen, 
   // we may need to do multiple iterations to achieve the desired compute
   // time on this system.
   double allItersSec = 0;
   uint32_t numTest = 1;
   while(allItersSec < 0.02)
   {
      numTest *= 2;
      TIMER_RESTART("KDF_Time_Search");
      for(uint32_t i=0; i<numTest; i++)
      {
         SecureBinaryData testKey("This is an example key to test KDF iteration speed");
         testKey = DeriveKey_OneIter(testKey);
      }
      TIMER_STOP("KDF_Time_Search");
      allItersSec = TIMER_READ_SEC("KDF_Time_Search");
   }

   double perIterSec  = allItersSec / numTest;
   numIterations_ = (uint32_t)(targetComputeSec / (perIterSec+0.0005));
   numIterations_ = (numIterations_ < 1 ? 1 : numIterations_);
   //cout << "System speed test results    :  " << endl;
   //cout << "   Total test of the KDF took:  " << allItersSec*1000 << " ms" << endl;
   //cout << "                   to execute:  " << numTest << " iterations" << endl;
   //cout << "   Target computation time is:  " << targetComputeSec*1000 << " ms" << endl;
   //cout << "   Setting numIterations to:    " << numIterations_ << endl;
}



/////////////////////////////////////////////////////////////////////////////
void KdfRomix::usePrecomputedKdfParams(uint32_t memReqts, 
                                       uint32_t numIter, 
                                       SecureBinaryData salt)
{
   memoryReqtBytes_ = memReqts;
   sequenceCount_   = memoryReqtBytes_ / hashOutputBytes_;
   numIterations_   = numIter;
   salt_            = salt;
}

/////////////////////////////////////////////////////////////////////////////
void KdfRomix::printKdfParams(void)
{
   // SHA512 computes 64-byte outputs
   cout << "KDF Parameters:" << endl;
   cout << "   HashFunction : " << hashFunctionName_ << endl;
   cout << "   HashOutBytes : " << hashOutputBytes_ << endl;
   cout << "   Memory/thread: " << memoryReqtBytes_ << " bytes" << endl;
   cout << "   SequenceCount: " << sequenceCount_   << endl;
   cout << "   NumIterations: " << numIterations_   << endl;
   cout << "   KDFOutBytes  : " << kdfOutputBytes_  << endl;
   cout << "   Salt         : " << salt_.toHexStr() << endl;
}


/////////////////////////////////////////////////////////////////////////////
SecureBinaryData KdfRomix::DeriveKey_OneIter(SecureBinaryData const & password)
{
   static CryptoPP::SHA512 sha512;

   // Concatenate the salt/IV to the password
   SecureBinaryData saltedPassword = password + salt_; 
   
   // Prepare the lookup table
   lookupTable_.resize(memoryReqtBytes_);
   lookupTable_.fill(0);
   uint32_t const HSZ = hashOutputBytes_;
   uint8_t* frontOfLUT = lookupTable_.getPtr();
   uint8_t* nextRead  = NULL;
   uint8_t* nextWrite = NULL;

   // First hash to seed the lookup table, input is variable length anyway
   sha512.CalculateDigest(frontOfLUT, 
                          saltedPassword.getPtr(), 
                          saltedPassword.getSize());

   // Compute <sequenceCount_> consecutive hashes of the passphrase
   // Every iteration is stored in the next 64-bytes in the Lookup table
   for(uint32_t nByte=0; nByte<memoryReqtBytes_-HSZ; nByte+=HSZ)
   {
      // Compute hash of slot i, put result in slot i+1
      nextRead  = frontOfLUT + nByte;
      nextWrite = nextRead + hashOutputBytes_;
      sha512.CalculateDigest(nextWrite, nextRead, hashOutputBytes_);
   }

   // LookupTable should be complete, now start lookup sequence.
   // Start with the last hash from the previous step
   SecureBinaryData X(frontOfLUT + memoryReqtBytes_ - HSZ, HSZ);
   SecureBinaryData Y(HSZ);

   // We "integerize" a hash value by taking the last 4 bytes of
   // as a uint32_t, and take modulo sequenceCount
   uint64_t* X64ptr = (uint64_t*)(X.getPtr());
   uint64_t* Y64ptr = (uint64_t*)(Y.getPtr());
   uint64_t* V64ptr = NULL;
   uint32_t newIndex;
   uint32_t const nXorOps = HSZ/sizeof(uint64_t);

   // Pure ROMix would use sequenceCount_ for the number of lookups.
   // We divide by 2 to reduce computation time RELATIVE to the memory usage
   // This still provides suffient LUT operations, but allows us to use more
   // memory in the same amount of time (and this is the justification for
   // the scrypt algorithm -- it is basically ROMix, modified for more 
   // flexibility in controlling compute-time vs memory-usage).
   uint32_t const nLookups = sequenceCount_ / 2;
   for(uint32_t nSeq=0; nSeq<nLookups; nSeq++)
   {
      // Interpret last 4 bytes of last result (mod seqCt) as next LUT index
      newIndex = *(uint32_t*)(X.getPtr()+HSZ-4) % sequenceCount_;

      // V represents the hash result at <newIndex>
      V64ptr = (uint64_t*)(frontOfLUT + HSZ*newIndex);

      // xor X with V, and store the result in X
      for(int i=0; i<nXorOps; i++)
         *(Y64ptr+i) = *(X64ptr+i) ^ *(V64ptr+i);

      // Hash the xor'd data to get the next index for lookup
      sha512.CalculateDigest(X.getPtr(), Y.getPtr(), HSZ);
   }
   // Truncate the final result to get the final key
   lookupTable_.destroy();
   return X.getSliceCopy(0,kdfOutputBytes_);
}

/////////////////////////////////////////////////////////////////////////////
SecureBinaryData KdfRomix::DeriveKey(SecureBinaryData const & password)
{
   SecureBinaryData masterKey(password);
   for(uint32_t i=0; i<numIterations_; i++)
      masterKey = DeriveKey_OneIter(masterKey);
   
   return SecureBinaryData(masterKey);
}





/////////////////////////////////////////////////////////////////////////////
// Implement AES encryption using AES mode, CFB
SecureBinaryData CryptoAES::EncryptCFB(SecureBinaryData & data, 
                                       SecureBinaryData & key,
                                       SecureBinaryData & iv)
{
   if(CRYPTO_DEBUG)
   {
      cout << "AES Decrypt" << endl;
      cout << "   BinData: " << data.toHexStr() << endl;
      cout << "   BinKey : " << key.toHexStr() << endl;
      cout << "   BinIV  : " << iv.toHexStr() << endl;
   }


   if(data.getSize() == 0)
      return SecureBinaryData(0);

   SecureBinaryData encrData(data.getSize());

   // Caller can supply their own IV/entropy, or let it be generated here
   // (variable "iv" is a reference, so check it on the way out)
   if(iv.getSize() == 0)
      iv = SecureBinaryData().GenerateRandom(BTC_AES::BLOCKSIZE);


   BTC_CFB_MODE<BTC_AES>::Encryption aes_enc( (byte*)key.getPtr(), 
                                                     key.getSize(), 
                                              (byte*)iv.getPtr());

   aes_enc.ProcessData( (byte*)encrData.getPtr(), 
                        (byte*)data.getPtr(), 
                               data.getSize());

   return encrData;
}

/////////////////////////////////////////////////////////////////////////////
// Implement AES decryption using AES mode, CFB
SecureBinaryData CryptoAES::DecryptCFB(SecureBinaryData & data, 
                                       SecureBinaryData & key,
                                       SecureBinaryData   iv  )
{
   if(CRYPTO_DEBUG)
   {
      cout << "AES Decrypt" << endl;
      cout << "   BinData: " << data.toHexStr() << endl;
      cout << "   BinKey : " << key.toHexStr() << endl;
      cout << "   BinIV  : " << iv.toHexStr() << endl;
   }


   if(data.getSize() == 0)
      return SecureBinaryData(0);

   SecureBinaryData unencrData(data.getSize());

   BTC_CFB_MODE<BTC_AES>::Decryption aes_enc( (byte*)key.getPtr(), 
                                                     key.getSize(), 
                                              (byte*)iv.getPtr());

   aes_enc.ProcessData( (byte*)unencrData.getPtr(), 
                        (byte*)data.getPtr(), 
                               data.getSize());

   return unencrData;
}



/////////////////////////////////////////////////////////////////////////////
// Same as above, but only changing the AES mode of operation (CBC, not CFB)
SecureBinaryData CryptoAES::EncryptCBC(SecureBinaryData & data, 
                                       SecureBinaryData & key,
                                       SecureBinaryData & iv)
{
   if(CRYPTO_DEBUG)
   {
      cout << "AES Decrypt" << endl;
      cout << "   BinData: " << data.toHexStr() << endl;
      cout << "   BinKey : " << key.toHexStr() << endl;
      cout << "   BinIV  : " << iv.toHexStr() << endl;
   }

   if(data.getSize() == 0)
      return SecureBinaryData(0);

   SecureBinaryData encrData(data.getSize());

   // Caller can supply their own IV/entropy, or let it be generated here
   // (variable "iv" is a reference, so check it on the way out)
   if(iv.getSize() == 0)
      iv = SecureBinaryData().GenerateRandom(BTC_AES::BLOCKSIZE);


   BTC_CBC_MODE<BTC_AES>::Encryption aes_enc( (byte*)key.getPtr(), 
                                                     key.getSize(), 
                                              (byte*)iv.getPtr());

   aes_enc.ProcessData( (byte*)encrData.getPtr(), 
                        (byte*)data.getPtr(), 
                               data.getSize());

   return encrData;
}

/////////////////////////////////////////////////////////////////////////////
// Same as above, but only changing the AES mode of operation (CBC, not CFB)
SecureBinaryData CryptoAES::DecryptCBC(SecureBinaryData & data, 
                                       SecureBinaryData & key,
                                       SecureBinaryData   iv  )
{
   if(CRYPTO_DEBUG)
   {
      cout << "AES Decrypt" << endl;
      cout << "   BinData: " << data.toHexStr() << endl;
      cout << "   BinKey : " << key.toHexStr() << endl;
      cout << "   BinIV  : " << iv.toHexStr() << endl;
   }

   if(data.getSize() == 0)
      return SecureBinaryData(0);

   SecureBinaryData unencrData(data.getSize());

   BTC_CBC_MODE<BTC_AES>::Decryption aes_enc( (byte*)key.getPtr(), 
                                                     key.getSize(), 
                                              (byte*)iv.getPtr());

   aes_enc.ProcessData( (byte*)unencrData.getPtr(), 
                        (byte*)data.getPtr(), 
                               data.getSize());
   return unencrData;
}




/////////////////////////////////////////////////////////////////////////////
EC_PRIVKEY CryptoECDSA::CreateNewPrivateKey(void)
{
   return ParsePrivateKey(SecureBinaryData().GenerateRandom(32));
}

/////////////////////////////////////////////////////////////////////////////
EC_PRIVKEY CryptoECDSA::ParsePrivateKey(SecureBinaryData const & privKeyData)
{
   EC_PRIVKEY cppPrivKey;

   CryptoPP::Integer privateExp;
   privateExp.Decode(privKeyData.getPtr(), privKeyData.getSize(), UNSIGNED);
   cppPrivKey.Initialize(EC_CURVE, privateExp);
   return cppPrivKey;
}


/////////////////////////////////////////////////////////////////////////////
EC_PUBKEY CryptoECDSA::ParsePublicKey(SecureBinaryData const & pubKey33or65)
{
   CryptoPP::ECP & ecp = Get_secp256k1_ECP();
   EC_PUBKEY btcPubKey;
   EC_POINT pubPt;
   ecp.DecodePoint(pubPt, (byte*)pubKey33or65.getPtr(), pubKey33or65.getSize());

   btcPubKey.Initialize(EC_CURVE, pubPt);
   return btcPubKey;
}


/////////////////////////////////////////////////////////////////////////////
SecureBinaryData CryptoECDSA::SerializePrivateKey(EC_PRIVKEY const & privKey)
{
   CryptoPP::Integer privateExp = privKey.GetPrivateExponent();
   SecureBinaryData privKeyData(32);
   privateExp.Encode(privKeyData.getPtr(), privKeyData.getSize(), UNSIGNED);
   return privKeyData;
}
   
/////////////////////////////////////////////////////////////////////////////
SecureBinaryData CryptoECDSA::SerializePublicKey(EC_PUBKEY const & pubKey,
                                                 bool doCompress)
{
   CryptoPP::ECP & ecp = Get_secp256k1_ECP();
   EC_POINT publicPoint = pubKey.GetPublicElement();
   if(doCompress)
   {
      SecureBinaryData pubData(33);
      ecp.EncodePoint((byte*)pubData.getPtr(), publicPoint, true);
      return pubData;
   }
   else
   {
      SecureBinaryData pubData(65);
      ecp.EncodePoint((byte*)pubData.getPtr(), publicPoint, false);
      return pubData;
   }
}

/////////////////////////////////////////////////////////////////////////////
SecureBinaryData CryptoECDSA::ComputePublicKey(SecureBinaryData const & cppPrivKey,
                                               bool doCompress)
{
   EC_PRIVKEY pk = ParsePrivateKey(cppPrivKey);
   EC_PUBKEY  pub;
   pk.MakePublicKey(pub);
   return SerializePublicKey(pub, doCompress);
}

/////////////////////////////////////////////////////////////////////////////
EC_PUBKEY CryptoECDSA::ComputePublicKey(EC_PRIVKEY const & cppPrivKey)
{
   EC_PUBKEY cppPubKey;
   cppPrivKey.MakePublicKey(cppPubKey);

   // Validate the public key -- not sure why this needs a prng...
   static CRYPTO_PRNG prng;
   assert(cppPubKey.Validate(prng, 3));
   assert(cppPubKey.Validate(prng, 3));

   return cppPubKey;
}

////////////////////////////////////////////////////////////////////////////////
SecureBinaryData CryptoECDSA::GenerateNewPrivateKey(void)
{
   return SecureBinaryData().GenerateRandom(32);
}


////////////////////////////////////////////////////////////////////////////////
bool CryptoECDSA::CheckPubPrivKeyMatch(EC_PRIVKEY const & cppPrivKey,
                                       EC_PUBKEY  const & cppPubKey)
{
   EC_PUBKEY computedPubKey;
   cppPrivKey.MakePublicKey(computedPubKey);
   
   EC_POINT ppA = cppPubKey.GetPublicElement();
   EC_POINT ppB = computedPubKey.GetPublicElement();
   return (ppA.x==ppB.x && ppA.y==ppB.y);
}

/////////////////////////////////////////////////////////////////////////////
bool CryptoECDSA::CheckPubPrivKeyMatch(SecureBinaryData const & privKey32,
                                       SecureBinaryData const & pubKey33or65)
{
   if(CRYPTO_DEBUG)
   {
      cout << "CheckPubPrivKeyMatch:" << endl;
      cout << "   BinPrv: " << privKey32.toHexStr() << endl;
      cout << "   BinPub: " << pubKey33or65.toHexStr() << endl;
   }

   EC_PRIVKEY privKey = ParsePrivateKey(privKey32);
   EC_PUBKEY  pubKey  = ParsePublicKey(pubKey33or65);
   return CheckPubPrivKeyMatch(privKey, pubKey);
}

/////////////////////////////////////////////////////////////////////////////
bool CryptoECDSA::VerifyPublicKeyValid(SecureBinaryData const & pubKey33or65)
{
   CryptoPP::ECP & ecp = Get_secp256k1_ECP();

   if(CRYPTO_DEBUG)
      cout << "BinPub: " << pubKey33or65.toHexStr() << endl;

   EC_PUBKEY btcPubKey;
   EC_POINT pubPt;
   ecp.DecodePoint(pubPt, (byte*)pubKey33or65.getPtr(), 
                                   pubKey33or65.getSize());

   btcPubKey.Initialize(EC_CURVE, pubPt);

   // Validate the public key -- not sure why this needs a PRNG
   static CRYPTO_PRNG prng;
   return btcPubKey.Validate(prng, 3);
}

/////////////////////////////////////////////////////////////////////////////
SecureBinaryData CryptoECDSA::SignData(SecureBinaryData const & binToSign, 
                                       SecureBinaryData const & binPrivKey)
{
   if(CRYPTO_DEBUG)
   {
      cout << "SignData:" << endl;
      cout << "   BinSgn: " << binToSign.getSize() << " " << binToSign.toHexStr() << endl;
      cout << "   BinPrv: " << binPrivKey.getSize() << " " << binPrivKey.toHexStr() << endl;
   }
   EC_PRIVKEY cppPrivKey = ParsePrivateKey(binPrivKey);
   return SignData(binToSign, cppPrivKey);
}

/////////////////////////////////////////////////////////////////////////////
SecureBinaryData CryptoECDSA::SignData(SecureBinaryData const & binToSign, 
                                       EC_PRIVKEY const & cppPrivKey)
{

   // We trick the Crypto++ ECDSA module by passing it a single-hashed
   // message, it will do the second hash before it signs it.  This is 
   // exactly what we need.
   static CryptoPP::SHA256  sha256;
   static CRYPTO_PRNG prng;

   // Execute the first sha256 op -- the signer will do the other one
   SecureBinaryData hashVal(32);
   sha256.CalculateDigest(hashVal.getPtr(), 
                          binToSign.getPtr(), 
                          binToSign.getSize());

   string signature;
   EC_SIGNER signer(cppPrivKey);
   CryptoPP::StringSource(
               hashVal.toBinStr(), true, new CryptoPP::SignerFilter(
               prng, signer, new CryptoPP::StringSink(signature))); 
  
   return SecureBinaryData(signature);
}


/////////////////////////////////////////////////////////////////////////////
bool CryptoECDSA::VerifyData(SecureBinaryData const & binMessage, 
                             SecureBinaryData const & binSignature,
                             SecureBinaryData const & pubkey65B)
{
   if(CRYPTO_DEBUG)
   {
      cout << "VerifyData:" << endl;
      cout << "   BinMsg: " << binMessage.toHexStr() << endl;
      cout << "   BinSig: " << binSignature.toHexStr() << endl;
      cout << "   BinPub: " << pubkey65B.toHexStr() << endl;
   }

   EC_PUBKEY cppPubKey = ParsePublicKey(pubkey65B);
   return VerifyData(binMessage, binSignature, cppPubKey);
}

/////////////////////////////////////////////////////////////////////////////
bool CryptoECDSA::VerifyData(SecureBinaryData const & binMessage, 
                             SecureBinaryData const & binSignature,
                             EC_PUBKEY const & cppPubKey)
                            
{


   static CryptoPP::SHA256  sha256;
   static CryptoPP::AutoSeededRandomPool prng;

   assert(cppPubKey.Validate(prng, 3));

   // We execute the first SHA256 op, here.  Next one is done by Verifier
   SecureBinaryData hashVal(32);
   sha256.CalculateDigest(hashVal.getPtr(), 
                          binMessage.getPtr(), 
                          binMessage.getSize());

   // Verifying message 
   EC_VERIFIER verifier(cppPubKey); 
   return verifier.VerifyMessage((const byte*)hashVal.getPtr(), 
                                              hashVal.getSize(),
                                 (const byte*)binSignature.getPtr(), 
                                              binSignature.getSize());
}



////////////////////////////////////////////////////////////////////////////////
bool CryptoECDSA::ECVerifyPoint(BinaryData const & x,
                                BinaryData const & y)
{
   EC_PUBKEY cppPubKey;

   CryptoPP::Integer pubX;
   CryptoPP::Integer pubY;
   pubX.Decode(x.getPtr(), x.getSize(), UNSIGNED);
   pubY.Decode(y.getPtr(), y.getSize(), UNSIGNED);
   EC_POINT publicPoint(pubX, pubY);

   // Initialize the public key with the ECP point just created
   cppPubKey.Initialize(EC_CURVE, publicPoint);

   // Validate the public key -- not sure why this needs a PRNG
   static CRYPTO_PRNG prng;
   return cppPubKey.Validate(prng, 3);
}


////////////////////////////////////////////////////////////////////////////////
CryptoPP::ECP& CryptoECDSA::Get_secp256k1_ECP(void)
{
   static bool firstRun = true;
   static CryptoPP::ECP theECP;
   if(firstRun) 
   {
      BinaryData N = BinaryData::CreateFromHex(
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");
      BinaryData a = BinaryData::CreateFromHex(
            "0000000000000000000000000000000000000000000000000000000000000000");
      BinaryData b = BinaryData::CreateFromHex(
           "0000000000000000000000000000000000000000000000000000000000000007");

      CryptoPP::Integer intN, inta, intb;

      intN.Decode( N.getPtr(),  N.getSize(),  UNSIGNED);
      inta.Decode( a.getPtr(),  a.getSize(),  UNSIGNED);
      intb.Decode( b.getPtr(),  b.getSize(),  UNSIGNED);
  
      theECP = CryptoPP::ECP(intN, inta, intb);
   }
   return theECP;
}




////////////////////////////////////////////////////////////////////////////////
BinaryData CryptoECDSA::ECMultiplyScalars(BinaryData const & A, 
                                          BinaryData const & B)
{
   // Hardcode the order of the secp256k1 EC group
   static BinaryData N = BinaryData::CreateFromHex(
           "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");

   CryptoPP::Integer intA, intB, intC, intN;
   intA.Decode(A.getPtr(), A.getSize(), UNSIGNED);
   intB.Decode(B.getPtr(), B.getSize(), UNSIGNED);
   intN.Decode(N.getPtr(), N.getSize(), UNSIGNED);
   intC = a_times_b_mod_c(intA, intB, intN);

   BinaryData C(32);
   intC.Encode(C.getPtr(), 32, UNSIGNED);
   return C;
}


////////////////////////////////////////////////////////////////////////////////
BinaryData CryptoECDSA::ECAddPoints(BinaryData const & Ax, 
                                    BinaryData const & Ay,
                                    BinaryData const & Bx,
                                    BinaryData const & By)
{
   CryptoPP::ECP ecp = Get_secp256k1_ECP();
   CryptoPP::Integer intAx, intAy, intBx, intBy, intCx, intCy;

   intAx.Decode(Ax.getPtr(), Ax.getSize(), UNSIGNED);
   intAy.Decode(Ay.getPtr(), Ay.getSize(), UNSIGNED);
   intBx.Decode(Bx.getPtr(), Bx.getSize(), UNSIGNED);
   intBy.Decode(By.getPtr(), By.getSize(), UNSIGNED);


   EC_POINT A(intAx, intAy);
   EC_POINT B(intBx, intBy);

   EC_POINT C = ecp.Add(A,B);

   BinaryData Cbd(64);
   C.x.Encode(Cbd.getPtr(),    32, UNSIGNED);
   C.y.Encode(Cbd.getPtr()+32, 32, UNSIGNED);

   return Cbd;
}


////////////////////////////////////////////////////////////////////////////////
BinaryData CryptoECDSA::ECInverse(BinaryData const & Ax, 
                                  BinaryData const & Ay)
                                  
{
   CryptoPP::ECP & ecp = Get_secp256k1_ECP();
   CryptoPP::Integer intAx, intAy, intCx, intCy;

   intAx.Decode(Ax.getPtr(), Ax.getSize(), UNSIGNED);
   intAy.Decode(Ay.getPtr(), Ay.getSize(), UNSIGNED);

   EC_POINT A(intAx, intAy);
   EC_POINT C = ecp.Inverse(A);

   BinaryData Cbd(64);
   C.x.Encode(Cbd.getPtr(),    32, UNSIGNED);
   C.y.Encode(Cbd.getPtr()+32, 32, UNSIGNED);

   return Cbd;
}


////////////////////////////////////////////////////////////////////////////////
SecureBinaryData CryptoECDSA::CompressPoint(SecureBinaryData const & pubKey65)
{
   if(pubKey65.getSize() == 33)
      return pubKey65;  // already compressed

   CryptoPP::ECP & ecp = Get_secp256k1_ECP();
   EC_POINT ptPub;
   ecp.DecodePoint(ptPub, (byte*)pubKey65.getPtr(), 65);
   SecureBinaryData ptCompressed(33);
   ecp.EncodePoint((byte*)ptCompressed.getPtr(), ptPub, true);
   return ptCompressed; 
}

////////////////////////////////////////////////////////////////////////////////
SecureBinaryData CryptoECDSA::UncompressPoint(SecureBinaryData const & pubKey33)
{
   if(pubKey33.getSize() == 65)
      return pubKey33;  // already uncompressed

   CryptoPP::ECP & ecp = Get_secp256k1_ECP();
   EC_POINT ptPub;
   ecp.DecodePoint(ptPub, (byte*)pubKey33.getPtr(), 33);
   SecureBinaryData ptUncompressed(65);
   ecp.EncodePoint((byte*)ptUncompressed.getPtr(), ptPub, false);
   return ptUncompressed; 

}



////////////////////////////////////////////////////////////////////////////////
// This function will eventually replace CryptoPP::ECMultiplyPoint, but I left
// the old one in so I can verify the new one before fully replacing it.
SecureBinaryData CryptoECDSA::ECMultiplyPoint(SecureBinaryData const & scalar, 
                                              SecureBinaryData const & ecPoint,
                                              bool compressOutput)
{
   CryptoPP::ECP ecp = Get_secp256k1_ECP();
   EC_PUBKEY btcPubKey = CryptoECDSA().ParsePublicKey(ecPoint);
   EC_POINT ecPubPt = btcPubKey.GetPublicElement();
   CryptoPP::Integer intScalar;
   intScalar.Decode(scalar.getPtr(), scalar.getSize(), UNSIGNED);
   EC_POINT newPubPt = ecp.ScalarMultiply(ecPubPt, intScalar);

   if(compressOutput)
   {
      SecureBinaryData out(33);
      ecp.EncodePoint((byte*)out.getPtr(), newPubPt, true);
   }
   else
   {
      SecureBinaryData out(65);
      ecp.EncodePoint((byte*)out.getPtr(), newPubPt, false);
   }

   
}


////////////////////////////////////////////////////////////////////////////////
// This function will eventually replace CryptoPP::ECMultiplyPoint, but I left
// the old one in so I can verify the new one before fully replacing it.
BinaryData CryptoECDSA::ECMultiplyPoint(BinaryData const & scalar, 
                                        BinaryData const & ecPoint,
                                        bool compressOutput)
{
   CryptoPP::ECP ecp = Get_secp256k1_ECP();
   EC_PUBKEY btcPubKey = CryptoECDSA().ParsePublicKey(ecPoint);
   EC_POINT ecPubPt = btcPubKey.GetPublicElement();
   CryptoPP::Integer intScalar;
   intScalar.Decode(scalar.getPtr(), scalar.getSize(), UNSIGNED);
   EC_POINT newPubPt = ecp.ScalarMultiply(ecPubPt, intScalar);

   if(compressOutput)
   {
      BinaryData out(33);
      ecp.EncodePoint((byte*)out.getPtr(), newPubPt, true);
   }
   else
   {
      BinaryData out(65);
      ecp.EncodePoint((byte*)out.getPtr(), newPubPt, false);
   }

   
}






////////////////////////////////////////////////////////////////////////////////
SecureBinaryData HDWalletCrypto::HMAC_SHA512(SecureBinaryData key, 
                                             SecureBinaryData msg)
{
   static CryptoPP::SHA512 sha512;
   static uint32_t const BLOCKSIZE = 64;

   // Reduce large keys via hash-function
   if(key.getSize() > BLOCKSIZE)
   {
      sha512.CalculateDigest(key.getPtr(), key.getPtr(), key.getSize());
      key.resize(BLOCKSIZE);
   }

   // Zero-pad smaller keys
   if(key.getSize() < BLOCKSIZE)
   {
      BinaryData zeros = BinaryData(BLOCKSIZE - key.getSize());
      zeros.fill(0x00);
      key.append(zeros);
   }
    

   SecureBinaryData o_key_pad = SecureBinaryData().XOR( key, 0x5c );
   SecureBinaryData i_key_pad = SecureBinaryData().XOR( key, 0x36 );

   // Inner hash operation
   i_key_pad.append(msg);
   sha512.CalculateDigest( i_key_pad.getPtr(), 
                           i_key_pad.getPtr(), 
                           i_key_pad.getSize() );  
   i_key_pad.resize(BLOCKSIZE);

   // Outer hash operation
   o_key_pad.append(i_key_pad);
   sha512.CalculateDigest( o_key_pad.getPtr(),
                           o_key_pad.getPtr(), 
                           o_key_pad.getSize() );  
   o_key_pad.resize(BLOCKSIZE);
   
   return o_key_pad;
}


////////////////////////////////////////////////////////////////////////////////
// In the HDWallet gist by Sipa, CKD takes two inputs:
//    1.  (Key, Chain) pair         (parent extended key)
//    2.  Index n
//
// Here, we supply a private key as the first arg if we are computing 
// the child of a private key.  Pass in a zero-length SBD object if 
// only computing child of a public key.
//
// We pass in the indexN as an already-big-endian-encoded 32-byte string
// I leave it up to the caller so that this function can be endian-agnostic
ExtendedKey HDWalletCrypto::ChildKeyDeriv( ExtendedKey extKey,
                                           SecureBinaryData indexN)
{
   // Can't compute a child with no parent!
   assert(extKey.isInitialized());

   // Make a copy of the public key, make sure it's uncompressed
   SecureBinaryData uncomprKey = CryptoECDSA().UncompressPoint(extKey.getPub());

   // Append the 32-byte index number to the uncompressed public key
   uncomprKey.append(indexN);

   // Apply HMAC to get the child pieces
   SecureBinaryData I = HMAC_SHA512(extKey.getChain(), uncomprKey);
   SecureBinaryData I_left(  I.getPtr(),     32 );
   SecureBinaryData I_right( I.getPtr()+32,  32 );

   SecureBinaryData newKey;

   if(extKey.hasPriv())
   {
      // This computes the private key, and lets ExtendedKey compute pub
      newKey = CryptoECDSA().ECMultiplyScalars(I_left, extKey.getPriv());
      return ExtendedKey().CreateFromPrivate(newKey, I_right);
   }
   else
   {
      // Compress the output if the we received compressed input
      bool doCompress = (extKey.getPub().getSize()==33);
      newKey = CryptoECDSA().ECMultiplyPoint(I_left, extKey.getPub(), doCompress);
      return ExtendedKey().CreateFromPublic(newKey, I_right);
   }
}






















/////////////////////////////////////////////////////////////////////////////

/////////////////////////////////////////////////////////////////////////////

/////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////
//
//
// These are precisely the methods used for wallet version 1.35 and lower.
// It's a lot of redundancy, but those wallets received a lot of testing,
// and never had any problems.  I want to maintain support for them and not
// risk breaking them by modifying existing methods to accommodate new 
// methods...
//
//
/////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////

/////////////////////////////////////////////////////////////////////////////

/////////////////////////////////////////////////////////////////////////////



/////////////////////////////////////////////////////////////////////////////
// We have to explicitly re-define some of these methods...
SecureBinaryData_1_35 & SecureBinaryData_1_35::append(SecureBinaryData_1_35 & sbd2) 
{
   if(sbd2.getSize()==0) 
      return (*this);

   if(getSize()==0) 
      BinaryData::copyFrom(sbd2.getPtr(), sbd2.getSize());
   else
      BinaryData::append(sbd2.getRawRef());

   lockData();
   return (*this);
}

/////////////////////////////////////////////////////////////////////////////
SecureBinaryData_1_35 SecureBinaryData_1_35::operator+(SecureBinaryData_1_35 & sbd2) const
{
   SecureBinaryData_1_35 out(getSize() + sbd2.getSize());
   memcpy(out.getPtr(), getPtr(), getSize());
   memcpy(out.getPtr()+getSize(), sbd2.getPtr(), sbd2.getSize());
   out.lockData();
   return out;
}

/////////////////////////////////////////////////////////////////////////////
SecureBinaryData_1_35 & SecureBinaryData_1_35::operator=(SecureBinaryData_1_35 const & sbd2)
{ 
   copyFrom(sbd2.getPtr(), sbd2.getSize() );
   lockData(); 
   return (*this);
}

/////////////////////////////////////////////////////////////////////////////
bool SecureBinaryData_1_35::operator==(SecureBinaryData_1_35 const & sbd2) const
{ 
   if(getSize() != sbd2.getSize())
      return false;
   for(unsigned int i=0; i<getSize(); i++)
      if( (*this)[i] != sbd2[i] )
         return false;
   return true;
}

/////////////////////////////////////////////////////////////////////////////
// Swap endianness of the bytes in the index range [pos1, pos2)
SecureBinaryData_1_35 SecureBinaryData_1_35::copySwapEndian(size_t pos1, size_t pos2) const
{
   return SecureBinaryData_1_35(BinaryData::copySwapEndian(pos1, pos2));
}

/////////////////////////////////////////////////////////////////////////////
SecureBinaryData_1_35 SecureBinaryData_1_35::GenerateRandom(uint32_t numBytes)
{
   static CryptoPP::AutoSeededRandomPool prng;
   SecureBinaryData_1_35 randData(numBytes);
   prng.GenerateBlock(randData.getPtr(), numBytes);
   return randData;  
}

/////////////////////////////////////////////////////////////////////////////
KdfRomix_1_35::KdfRomix_1_35(void) : 
   hashFunctionName_( "sha512" ),
   hashOutputBytes_( 64 ),
   kdfOutputBytes_( 32 ),
   memoryReqtBytes_( 32 ),
   numIterations_( 0 )
{ 
   // Nothing to do here
}

/////////////////////////////////////////////////////////////////////////////
KdfRomix_1_35::KdfRomix_1_35(uint32_t memReqts, uint32_t numIter, SecureBinaryData_1_35 salt) :
   hashFunctionName_( "sha512" ),
   hashOutputBytes_( 64 ),
   kdfOutputBytes_( 32 )
{
   usePrecomputedKdfParams(memReqts, numIter, salt);
}

/////////////////////////////////////////////////////////////////////////////
void KdfRomix_1_35::computeKdfParams(double targetComputeSec, uint32_t maxMemReqts)
{
   // Create a random salt, even though this is probably unnecessary:
   // the variation in numIter and memReqts is probably effective enough
   salt_ = SecureBinaryData_1_35().GenerateRandom(32);

   // If target compute is 0s, then this method really only generates 
   // a random salt, and sets the other params to default minimum.
   if(targetComputeSec == 0)
   {
      numIterations_ = 1;
      memoryReqtBytes_ = 1024;
      return;
   }


   // Here, we pick the largest memory reqt that allows the executing system
   // to compute the KDF is less than the target time.  A maximum can be 
   // specified, in case the target system is likely to be memory-limited
   // more than compute-speed limited
   SecureBinaryData_1_35 testKey("This is an example key to test KDF iteration speed");

   // Start the search for a memory value at 1kB
   memoryReqtBytes_ = 1024;
   double approxSec = 0;
   while(approxSec <= targetComputeSec/4 && memoryReqtBytes_ < maxMemReqts)
   {
      memoryReqtBytes_ *= 2;

      sequenceCount_ = memoryReqtBytes_ / hashOutputBytes_;
      lookupTable_.resize(memoryReqtBytes_);

      TIMER_RESTART("KDF_Mem_Search");
      testKey = DeriveKey_OneIter(testKey);
      TIMER_STOP("KDF_Mem_Search");
      approxSec = TIMER_READ_SEC("KDF_Mem_Search");
   }

   // Recompute here, in case we didn't enter the search above 
   sequenceCount_ = memoryReqtBytes_ / hashOutputBytes_;
   lookupTable_.resize(memoryReqtBytes_);


   // Depending on the search above (or if a low max memory was chosen, 
   // we may need to do multiple iterations to achieve the desired compute
   // time on this system.
   double allItersSec = 0;
   uint32_t numTest = 1;
   while(allItersSec < 0.02)
   {
      numTest *= 2;
      TIMER_RESTART("KDF_Time_Search");
      for(uint32_t i=0; i<numTest; i++)
      {
         SecureBinaryData_1_35 testKey("This is an example key to test KDF iteration speed");
         testKey = DeriveKey_OneIter(testKey);
      }
      TIMER_STOP("KDF_Time_Search");
      allItersSec = TIMER_READ_SEC("KDF_Time_Search");
   }

   double perIterSec  = allItersSec / numTest;
   numIterations_ = (uint32_t)(targetComputeSec / (perIterSec+0.0005));
   numIterations_ = (numIterations_ < 1 ? 1 : numIterations_);
   //cout << "System speed test results    :  " << endl;
   //cout << "   Total test of the KDF took:  " << allItersSec*1000 << " ms" << endl;
   //cout << "                   to execute:  " << numTest << " iterations" << endl;
   //cout << "   Target computation time is:  " << targetComputeSec*1000 << " ms" << endl;
   //cout << "   Setting numIterations to:    " << numIterations_ << endl;
}



/////////////////////////////////////////////////////////////////////////////
void KdfRomix_1_35::usePrecomputedKdfParams(uint32_t memReqts, 
                                       uint32_t numIter, 
                                       SecureBinaryData_1_35 salt)
{
   memoryReqtBytes_ = memReqts;
   sequenceCount_   = memoryReqtBytes_ / hashOutputBytes_;
   numIterations_   = numIter;
   salt_            = salt;
}

/////////////////////////////////////////////////////////////////////////////
void KdfRomix_1_35::printKdfParams(void)
{
   // SHA512 computes 64-byte outputs
   cout << "KDF Parameters:" << endl;
   cout << "   HashFunction : " << hashFunctionName_ << endl;
   cout << "   HashOutBytes : " << hashOutputBytes_ << endl;
   cout << "   Memory/thread: " << memoryReqtBytes_ << " bytes" << endl;
   cout << "   SequenceCount: " << sequenceCount_   << endl;
   cout << "   NumIterations: " << numIterations_   << endl;
   cout << "   KDFOutBytes  : " << kdfOutputBytes_  << endl;
   cout << "   Salt         : " << salt_.toHexStr() << endl;
}


/////////////////////////////////////////////////////////////////////////////
SecureBinaryData_1_35 KdfRomix_1_35::DeriveKey_OneIter(SecureBinaryData_1_35 const & password)
{
   static CryptoPP::SHA512 sha512;

   // Concatenate the salt/IV to the password
   SecureBinaryData_1_35 saltedPassword = password + salt_; 
   
   // Prepare the lookup table
   lookupTable_.resize(memoryReqtBytes_);
   lookupTable_.fill(0);
   uint32_t const HSZ = hashOutputBytes_;
   uint8_t* frontOfLUT = lookupTable_.getPtr();
   uint8_t* nextRead  = NULL;
   uint8_t* nextWrite = NULL;

   // First hash to seed the lookup table, input is variable length anyway
   sha512.CalculateDigest(frontOfLUT, 
                          saltedPassword.getPtr(), 
                          saltedPassword.getSize());

   // Compute <sequenceCount_> consecutive hashes of the passphrase
   // Every iteration is stored in the next 64-bytes in the Lookup table
   for(uint32_t nByte=0; nByte<memoryReqtBytes_-HSZ; nByte+=HSZ)
   {
      // Compute hash of slot i, put result in slot i+1
      nextRead  = frontOfLUT + nByte;
      nextWrite = nextRead + hashOutputBytes_;
      sha512.CalculateDigest(nextWrite, nextRead, hashOutputBytes_);
   }

   // LookupTable should be complete, now start lookup sequence.
   // Start with the last hash from the previous step
   SecureBinaryData_1_35 X(frontOfLUT + memoryReqtBytes_ - HSZ, HSZ);
   SecureBinaryData_1_35 Y(HSZ);

   // We "integerize" a hash value by taking the last 4 bytes of
   // as a uint32_t, and take modulo sequenceCount
   uint64_t* X64ptr = (uint64_t*)(X.getPtr());
   uint64_t* Y64ptr = (uint64_t*)(Y.getPtr());
   uint64_t* V64ptr = NULL;
   uint32_t newIndex;
   uint32_t const nXorOps = HSZ/sizeof(uint64_t);

   // Pure ROMix would use sequenceCount_ for the number of lookups.
   // We divide by 2 to reduce computation time RELATIVE to the memory usage
   // This still provides suffient LUT operations, but allows us to use more
   // memory in the same amount of time (and this is the justification for
   // the scrypt algorithm -- it is basically ROMix, modified for more 
   // flexibility in controlling compute-time vs memory-usage).
   uint32_t const nLookups = sequenceCount_ / 2;
   for(uint32_t nSeq=0; nSeq<nLookups; nSeq++)
   {
      // Interpret last 4 bytes of last result (mod seqCt) as next LUT index
      newIndex = *(uint32_t*)(X.getPtr()+HSZ-4) % sequenceCount_;

      // V represents the hash result at <newIndex>
      V64ptr = (uint64_t*)(frontOfLUT + HSZ*newIndex);

      // xor X with V, and store the result in X
      for(int i=0; i<nXorOps; i++)
         *(Y64ptr+i) = *(X64ptr+i) ^ *(V64ptr+i);

      // Hash the xor'd data to get the next index for lookup
      sha512.CalculateDigest(X.getPtr(), Y.getPtr(), HSZ);
   }
   // Truncate the final result to get the final key
   lookupTable_.destroy();
   return X.getSliceCopy(0,kdfOutputBytes_);
}

/////////////////////////////////////////////////////////////////////////////
SecureBinaryData_1_35 KdfRomix_1_35::DeriveKey(SecureBinaryData_1_35 const & password)
{
   SecureBinaryData_1_35 masterKey(password);
   for(uint32_t i=0; i<numIterations_; i++)
      masterKey = DeriveKey_OneIter(masterKey);
   
   return SecureBinaryData_1_35(masterKey);
}





/////////////////////////////////////////////////////////////////////////////
// Implement AES encryption using AES mode, CFB
SecureBinaryData_1_35 CryptoAES_1_35::EncryptCFB(SecureBinaryData_1_35 & data, 
                                            SecureBinaryData_1_35 & key,
                                            SecureBinaryData_1_35 & iv)
{
   if(CRYPTO_DEBUG)
   {
      cout << "AES Decrypt" << endl;
      cout << "   BinData: " << data.toHexStr() << endl;
      cout << "   BinKey : " << key.toHexStr() << endl;
      cout << "   BinIV  : " << iv.toHexStr() << endl;
   }


   if(data.getSize() == 0)
      return SecureBinaryData_1_35(0);

   SecureBinaryData_1_35 encrData(data.getSize());

   // Caller can supply their own IV/entropy, or let it be generated here
   // (variable "iv" is a reference, so check it on the way out)
   if(iv.getSize() == 0)
      iv = SecureBinaryData_1_35().GenerateRandom(BTC_AES::BLOCKSIZE);


   BTC_CFB_MODE<BTC_AES>::Encryption aes_enc( (byte*)key.getPtr(), 
                                                     key.getSize(), 
                                              (byte*)iv.getPtr());

   aes_enc.ProcessData( (byte*)encrData.getPtr(), 
                        (byte*)data.getPtr(), 
                               data.getSize());

   return encrData;
}

/////////////////////////////////////////////////////////////////////////////
// Implement AES decryption using AES mode, CFB
SecureBinaryData_1_35 CryptoAES_1_35::DecryptCFB(SecureBinaryData_1_35 & data, 
                                       SecureBinaryData_1_35 & key,
                                       SecureBinaryData_1_35   iv  )
{
   if(CRYPTO_DEBUG)
   {
      cout << "AES Decrypt" << endl;
      cout << "   BinData: " << data.toHexStr() << endl;
      cout << "   BinKey : " << key.toHexStr() << endl;
      cout << "   BinIV  : " << iv.toHexStr() << endl;
   }


   if(data.getSize() == 0)
      return SecureBinaryData_1_35(0);

   SecureBinaryData_1_35 unencrData(data.getSize());

   BTC_CFB_MODE<BTC_AES>::Decryption aes_enc( (byte*)key.getPtr(), 
                                                     key.getSize(), 
                                              (byte*)iv.getPtr());

   aes_enc.ProcessData( (byte*)unencrData.getPtr(), 
                        (byte*)data.getPtr(), 
                               data.getSize());

   return unencrData;
}



/////////////////////////////////////////////////////////////////////////////
// Same as above, but only changing the AES mode of operation (CBC, not CFB)
SecureBinaryData_1_35 CryptoAES_1_35::EncryptCBC(SecureBinaryData_1_35 & data, 
                                       SecureBinaryData_1_35 & key,
                                       SecureBinaryData_1_35 & iv)
{
   if(CRYPTO_DEBUG)
   {
      cout << "AES Decrypt" << endl;
      cout << "   BinData: " << data.toHexStr() << endl;
      cout << "   BinKey : " << key.toHexStr() << endl;
      cout << "   BinIV  : " << iv.toHexStr() << endl;
   }

   if(data.getSize() == 0)
      return SecureBinaryData_1_35(0);

   SecureBinaryData_1_35 encrData(data.getSize());

   // Caller can supply their own IV/entropy, or let it be generated here
   // (variable "iv" is a reference, so check it on the way out)
   if(iv.getSize() == 0)
      iv = SecureBinaryData_1_35().GenerateRandom(BTC_AES::BLOCKSIZE);


   BTC_CBC_MODE<BTC_AES>::Encryption aes_enc( (byte*)key.getPtr(), 
                                                     key.getSize(), 
                                              (byte*)iv.getPtr());

   aes_enc.ProcessData( (byte*)encrData.getPtr(), 
                        (byte*)data.getPtr(), 
                               data.getSize());

   return encrData;
}

/////////////////////////////////////////////////////////////////////////////
// Same as above, but only changing the AES mode of operation (CBC, not CFB)
SecureBinaryData_1_35 CryptoAES_1_35::DecryptCBC(SecureBinaryData_1_35 & data, 
                                       SecureBinaryData_1_35 & key,
                                       SecureBinaryData_1_35   iv  )
{
   if(CRYPTO_DEBUG)
   {
      cout << "AES Decrypt" << endl;
      cout << "   BinData: " << data.toHexStr() << endl;
      cout << "   BinKey : " << key.toHexStr() << endl;
      cout << "   BinIV  : " << iv.toHexStr() << endl;
   }

   if(data.getSize() == 0)
      return SecureBinaryData_1_35(0);

   SecureBinaryData_1_35 unencrData(data.getSize());

   BTC_CBC_MODE<BTC_AES>::Decryption aes_enc( (byte*)key.getPtr(), 
                                                     key.getSize(), 
                                              (byte*)iv.getPtr());

   aes_enc.ProcessData( (byte*)unencrData.getPtr(), 
                        (byte*)data.getPtr(), 
                               data.getSize());
   return unencrData;
}




/////////////////////////////////////////////////////////////////////////////
BTC_PRIVKEY CryptoECDSA_1_35::CreateNewPrivateKey(void)
{
   return ParsePrivateKey(SecureBinaryData_1_35().GenerateRandom(32));
}

/////////////////////////////////////////////////////////////////////////////
BTC_PRIVKEY CryptoECDSA_1_35::ParsePrivateKey(SecureBinaryData_1_35 const & privKeyData)
{
   BTC_PRIVKEY cppPrivKey;

   CryptoPP::Integer privateExp;
   privateExp.Decode(privKeyData.getPtr(), privKeyData.getSize(), UNSIGNED);
   cppPrivKey.Initialize(CryptoPP::ASN1::secp256k1(), privateExp);
   return cppPrivKey;
}


/////////////////////////////////////////////////////////////////////////////
BTC_PUBKEY CryptoECDSA_1_35::ParsePublicKey(SecureBinaryData_1_35 const & pubKey65B)
{
   SecureBinaryData_1_35 pubXbin(pubKey65B.getSliceRef( 1,32));
   SecureBinaryData_1_35 pubYbin(pubKey65B.getSliceRef(33,32));
   return ParsePublicKey(pubXbin, pubYbin);
}

/////////////////////////////////////////////////////////////////////////////
BTC_PUBKEY CryptoECDSA_1_35::ParsePublicKey(SecureBinaryData_1_35 const & pubKeyX32B,
                                       SecureBinaryData_1_35 const & pubKeyY32B)
{
   BTC_PUBKEY cppPubKey;

   CryptoPP::Integer pubX;
   CryptoPP::Integer pubY;
   pubX.Decode(pubKeyX32B.getPtr(), pubKeyX32B.getSize(), UNSIGNED);
   pubY.Decode(pubKeyY32B.getPtr(), pubKeyY32B.getSize(), UNSIGNED);
   BTC_ECPOINT publicPoint(pubX, pubY);

   // Initialize the public key with the ECP point just created
   cppPubKey.Initialize(CryptoPP::ASN1::secp256k1(), publicPoint);

   // Validate the public key -- not sure why this needs a PRNG
   static BTC_PRNG prng;
   assert(cppPubKey.Validate(prng, 3));

   return cppPubKey;
}

/////////////////////////////////////////////////////////////////////////////
SecureBinaryData_1_35 CryptoECDSA_1_35::SerializePrivateKey(BTC_PRIVKEY const & privKey)
{
   CryptoPP::Integer privateExp = privKey.GetPrivateExponent();
   SecureBinaryData_1_35 privKeyData(32);
   privateExp.Encode(privKeyData.getPtr(), privKeyData.getSize(), UNSIGNED);
   return privKeyData;
}
   
/////////////////////////////////////////////////////////////////////////////
SecureBinaryData_1_35 CryptoECDSA_1_35::SerializePublicKey(BTC_PUBKEY const & pubKey)
{
   BTC_ECPOINT publicPoint = pubKey.GetPublicElement();
   CryptoPP::Integer pubX = publicPoint.x;
   CryptoPP::Integer pubY = publicPoint.y;
   SecureBinaryData_1_35 pubData(65);
   pubData.fill(0x04);  // we fill just to set the first byte...

   pubX.Encode(pubData.getPtr()+1,  32, UNSIGNED);
   pubY.Encode(pubData.getPtr()+33, 32, UNSIGNED);
   return pubData;
}

/////////////////////////////////////////////////////////////////////////////
SecureBinaryData_1_35 CryptoECDSA_1_35::ComputePublicKey(SecureBinaryData_1_35 const & cppPrivKey)
{
   BTC_PRIVKEY pk = ParsePrivateKey(cppPrivKey);
   BTC_PUBKEY  pub;
   pk.MakePublicKey(pub);
   return SerializePublicKey(pub);
}

/////////////////////////////////////////////////////////////////////////////
BTC_PUBKEY CryptoECDSA_1_35::ComputePublicKey(BTC_PRIVKEY const & cppPrivKey)
{
   BTC_PUBKEY cppPubKey;
   cppPrivKey.MakePublicKey(cppPubKey);

   // Validate the public key -- not sure why this needs a prng...
   static BTC_PRNG prng;
   assert(cppPubKey.Validate(prng, 3));
   assert(cppPubKey.Validate(prng, 3));

   return cppPubKey;
}

////////////////////////////////////////////////////////////////////////////////
SecureBinaryData_1_35 CryptoECDSA_1_35::GenerateNewPrivateKey(void)
{
   return SecureBinaryData_1_35().GenerateRandom(32);
}


////////////////////////////////////////////////////////////////////////////////
bool CryptoECDSA_1_35::CheckPubPrivKeyMatch(BTC_PRIVKEY const & cppPrivKey,
                                       BTC_PUBKEY  const & cppPubKey)
{
   BTC_PUBKEY computedPubKey;
   cppPrivKey.MakePublicKey(computedPubKey);
   
   BTC_ECPOINT ppA = cppPubKey.GetPublicElement();
   BTC_ECPOINT ppB = computedPubKey.GetPublicElement();
   return (ppA.x==ppB.x && ppA.y==ppB.y);
}

/////////////////////////////////////////////////////////////////////////////
bool CryptoECDSA_1_35::CheckPubPrivKeyMatch(SecureBinaryData_1_35 const & privKey32,
                                       SecureBinaryData_1_35 const & pubKey65)
{
   if(CRYPTO_DEBUG)
   {
      cout << "CheckPubPrivKeyMatch:" << endl;
      cout << "   BinPrv: " << privKey32.toHexStr() << endl;
      cout << "   BinPub: " << pubKey65.toHexStr() << endl;
   }

   BTC_PRIVKEY privKey = ParsePrivateKey(privKey32);
   BTC_PUBKEY  pubKey  = ParsePublicKey(pubKey65);
   return CheckPubPrivKeyMatch(privKey, pubKey);
}

bool CryptoECDSA_1_35::VerifyPublicKeyValid(SecureBinaryData_1_35 const & pubKey65)
{
   if(CRYPTO_DEBUG)
   {
      cout << "BinPub: " << pubKey65.toHexStr() << endl;
   }

   // Basically just copying the ParsePublicKey method, but without
   // the assert that would throw an error from C++
   SecureBinaryData_1_35 pubXbin(pubKey65.getSliceRef( 1,32));
   SecureBinaryData_1_35 pubYbin(pubKey65.getSliceRef(33,32));
   CryptoPP::Integer pubX;
   CryptoPP::Integer pubY;
   pubX.Decode(pubXbin.getPtr(), pubXbin.getSize(), UNSIGNED);
   pubY.Decode(pubYbin.getPtr(), pubYbin.getSize(), UNSIGNED);
   BTC_ECPOINT publicPoint(pubX, pubY);

   // Initialize the public key with the ECP point just created
   BTC_PUBKEY cppPubKey;
   cppPubKey.Initialize(CryptoPP::ASN1::secp256k1(), publicPoint);

   // Validate the public key -- not sure why this needs a PRNG
   static BTC_PRNG prng;
   return cppPubKey.Validate(prng, 3);
}

/////////////////////////////////////////////////////////////////////////////
SecureBinaryData_1_35 CryptoECDSA_1_35::SignData(SecureBinaryData_1_35 const & binToSign, 
                                       SecureBinaryData_1_35 const & binPrivKey)
{
   if(CRYPTO_DEBUG)
   {
      cout << "SignData:" << endl;
      cout << "   BinSgn: " << binToSign.getSize() << " " << binToSign.toHexStr() << endl;
      cout << "   BinPrv: " << binPrivKey.getSize() << " " << binPrivKey.toHexStr() << endl;
   }
   BTC_PRIVKEY cppPrivKey = ParsePrivateKey(binPrivKey);
   return SignData(binToSign, cppPrivKey);
}

/////////////////////////////////////////////////////////////////////////////
SecureBinaryData_1_35 CryptoECDSA_1_35::SignData(SecureBinaryData_1_35 const & binToSign, 
                                       BTC_PRIVKEY const & cppPrivKey)
{

   // We trick the Crypto++ ECDSA module by passing it a single-hashed
   // message, it will do the second hash before it signs it.  This is 
   // exactly what we need.
   static CryptoPP::SHA256  sha256;
   static BTC_PRNG prng;

   // Execute the first sha256 op -- the signer will do the other one
   SecureBinaryData_1_35 hashVal(32);
   sha256.CalculateDigest(hashVal.getPtr(), 
                          binToSign.getPtr(), 
                          binToSign.getSize());

   string signature;
   BTC_SIGNER signer(cppPrivKey);
   CryptoPP::StringSource(
               hashVal.toBinStr(), true, new CryptoPP::SignerFilter(
               prng, signer, new CryptoPP::StringSink(signature))); 
  
   return SecureBinaryData_1_35(signature);
}


/////////////////////////////////////////////////////////////////////////////
bool CryptoECDSA_1_35::VerifyData(SecureBinaryData_1_35 const & binMessage, 
                             SecureBinaryData_1_35 const & binSignature,
                             SecureBinaryData_1_35 const & pubkey65B)
{
   if(CRYPTO_DEBUG)
   {
      cout << "VerifyData:" << endl;
      cout << "   BinMsg: " << binMessage.toHexStr() << endl;
      cout << "   BinSig: " << binSignature.toHexStr() << endl;
      cout << "   BinPub: " << pubkey65B.toHexStr() << endl;
   }

   BTC_PUBKEY cppPubKey = ParsePublicKey(pubkey65B);
   return VerifyData(binMessage, binSignature, cppPubKey);
}

/////////////////////////////////////////////////////////////////////////////
bool CryptoECDSA_1_35::VerifyData(SecureBinaryData_1_35 const & binMessage, 
                             SecureBinaryData_1_35 const & binSignature,
                             BTC_PUBKEY const & cppPubKey)
                            
{


   static CryptoPP::SHA256  sha256;
   static CryptoPP::AutoSeededRandomPool prng;

   assert(cppPubKey.Validate(prng, 3));

   // We execute the first SHA256 op, here.  Next one is done by Verifier
   SecureBinaryData_1_35 hashVal(32);
   sha256.CalculateDigest(hashVal.getPtr(), 
                          binMessage.getPtr(), 
                          binMessage.getSize());

   // Verifying message 
   BTC_VERIFIER verifier(cppPubKey); 
   return verifier.VerifyMessage((const byte*)hashVal.getPtr(), 
                                              hashVal.getSize(),
                                 (const byte*)binSignature.getPtr(), 
                                              binSignature.getSize());
}

/////////////////////////////////////////////////////////////////////////////
// Deterministically generate new private key using a chaincode
// Changed:  added using the hash of the public key to the mix
//           b/c multiplying by the chaincode alone is too "linear"
//           (there's no reason to believe it's insecure, but it doesn't
//           hurt to add some extra entropy/non-linearity to the chain
//           generation process)
SecureBinaryData_1_35 CryptoECDSA_1_35::ComputeChainedPrivateKey(
                                 SecureBinaryData_1_35 const & binPrivKey,
                                 SecureBinaryData_1_35 const & chainCode,
                                 SecureBinaryData_1_35 binPubKey)
{
   if(CRYPTO_DEBUG)
   {
      cout << "ComputeChainedPrivateKey:" << endl;
      cout << "   BinPrv: " << binPrivKey.toHexStr() << endl;
      cout << "   BinChn: " << chainCode.toHexStr() << endl;
      cout << "   BinPub: " << binPubKey.toHexStr() << endl;
   }


   if( binPubKey.getSize()==0 )
      binPubKey = ComputePublicKey(binPrivKey);

   if( binPrivKey.getSize() != 32 || chainCode.getSize() != 32)
   {
      cerr << "***ERROR:  Invalid private key or chaincode (both must be 32B)";
      cerr << endl;
      cerr << "BinPrivKey: " << binPrivKey.getSize() << endl;
      cerr << "BinPrivKey: " << binPrivKey.toHexStr() << endl;
      cerr << "BinChain  : " << chainCode.getSize() << endl;
      cerr << "BinChain  : " << chainCode.toHexStr() << endl;
   }

   // Adding extra entropy to chaincode by xor'ing with hash256 of pubkey
   BinaryData chainMod  = binPubKey.getHash256();
   BinaryData chainOrig = chainCode.getRawCopy();
   BinaryData chainXor(32);
      
   for(uint8_t i=0; i<8; i++)
   {
      uint8_t offset = 4*i;
      *(uint32_t*)(chainXor.getPtr()+offset) =
                           *(uint32_t*)( chainMod.getPtr()+offset) ^ 
                           *(uint32_t*)(chainOrig.getPtr()+offset);
   }

   // Hard-code the order of the group
   static SecureBinaryData_1_35 SECP256K1_ORDER_BE = SecureBinaryData_1_35().CreateFromHex(
           "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
   
   CryptoPP::Integer chaincode, origPrivExp, ecOrder;
   // A 
   chaincode.Decode(chainXor.getPtr(), chainXor.getSize(), UNSIGNED);
   // B 
   origPrivExp.Decode(binPrivKey.getPtr(), binPrivKey.getSize(), UNSIGNED);
   // C
   ecOrder.Decode(SECP256K1_ORDER_BE.getPtr(), SECP256K1_ORDER_BE.getSize(), UNSIGNED);

   // A*B mod C will get us a new private key exponent
   CryptoPP::Integer newPrivExponent = 
                  a_times_b_mod_c(chaincode, origPrivExp, ecOrder);

   // Convert new private exponent to big-endian binary string 
   SecureBinaryData_1_35 newPrivData(32);
   newPrivExponent.Encode(newPrivData.getPtr(), newPrivData.getSize(), UNSIGNED);
   return newPrivData;
}
                            
/////////////////////////////////////////////////////////////////////////////
// Deterministically generate new public key using a chaincode
SecureBinaryData_1_35 CryptoECDSA_1_35::ComputeChainedPublicKey(
                                SecureBinaryData_1_35 const & binPubKey,
                                SecureBinaryData_1_35 const & chainCode)
{
   if(CRYPTO_DEBUG)
   {
      cout << "ComputeChainedPUBLICKey:" << endl;
      cout << "   BinPub: " << binPubKey.toHexStr() << endl;
      cout << "   BinChn: " << chainCode.toHexStr() << endl;
   }
   static SecureBinaryData_1_35 SECP256K1_ORDER_BE = SecureBinaryData_1_35::CreateFromHex(
           "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");

   // Added extra entropy to chaincode by xor'ing with hash256 of pubkey
   BinaryData chainMod  = binPubKey.getHash256();
   BinaryData chainOrig = chainCode.getRawCopy();
   BinaryData chainXor(32);
      
   for(uint8_t i=0; i<8; i++)
   {
      uint8_t offset = 4*i;
      *(uint32_t*)(chainXor.getPtr()+offset) =
                           *(uint32_t*)( chainMod.getPtr()+offset) ^ 
                           *(uint32_t*)(chainOrig.getPtr()+offset);
   }

   // Parse the chaincode as a big-endian integer
   CryptoPP::Integer chaincode;
   chaincode.Decode(chainXor.getPtr(), chainXor.getSize(), UNSIGNED);

   // "new" init as "old", to make sure it's initialized on the correct curve
   BTC_PUBKEY oldPubKey = ParsePublicKey(binPubKey); 
   BTC_PUBKEY newPubKey = ParsePublicKey(binPubKey);

   // Let Crypto++ do the EC math for us, serialize the new public key
   newPubKey.SetPublicElement( oldPubKey.ExponentiatePublicElement(chaincode) );
   return CryptoECDSA_1_35::SerializePublicKey(newPubKey);
}


////////////////////////////////////////////////////////////////////////////////
bool CryptoECDSA_1_35::ECVerifyPoint(BinaryData const & x,
                                BinaryData const & y)
{
   BTC_PUBKEY cppPubKey;

   CryptoPP::Integer pubX;
   CryptoPP::Integer pubY;
   pubX.Decode(x.getPtr(), x.getSize(), UNSIGNED);
   pubY.Decode(y.getPtr(), y.getSize(), UNSIGNED);
   BTC_ECPOINT publicPoint(pubX, pubY);

   // Initialize the public key with the ECP point just created
   cppPubKey.Initialize(CryptoPP::ASN1::secp256k1(), publicPoint);

   // Validate the public key -- not sure why this needs a PRNG
   static BTC_PRNG prng;
   return cppPubKey.Validate(prng, 3);
}


////////////////////////////////////////////////////////////////////////////////
CryptoPP::ECP& CryptoECDSA_1_35::Get_secp256k1_ECP(void)
{
   static bool firstRun = true;
   static CryptoPP::ECP theECP;
   if(firstRun) 
   {
      BinaryData N = BinaryData::CreateFromHex(
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");
      BinaryData a = BinaryData::CreateFromHex(
            "0000000000000000000000000000000000000000000000000000000000000000");
      BinaryData b = BinaryData::CreateFromHex(
           "0000000000000000000000000000000000000000000000000000000000000007");

      CryptoPP::Integer intN, inta, intb;

      intN.Decode( N.getPtr(),  N.getSize(),  UNSIGNED);
      inta.Decode( a.getPtr(),  a.getSize(),  UNSIGNED);
      intb.Decode( b.getPtr(),  b.getSize(),  UNSIGNED);
  
      theECP = CryptoPP::ECP(intN, inta, intb);
   }
   return theECP;
}




////////////////////////////////////////////////////////////////////////////////
BinaryData CryptoECDSA_1_35::ECMultiplyScalars(BinaryData const & A, 
                                          BinaryData const & B)
{
   // Hardcode the order of the secp256k1 EC group
   static BinaryData N = BinaryData::CreateFromHex(
           "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");

   CryptoPP::Integer intA, intB, intC, intN;
   intA.Decode(A.getPtr(), A.getSize(), UNSIGNED);
   intB.Decode(B.getPtr(), B.getSize(), UNSIGNED);
   intN.Decode(N.getPtr(), N.getSize(), UNSIGNED);
   intC = a_times_b_mod_c(intA, intB, intN);

   BinaryData C(32);
   intC.Encode(C.getPtr(), 32, UNSIGNED);
   return C;
}

////////////////////////////////////////////////////////////////////////////////
BinaryData CryptoECDSA_1_35::ECMultiplyPoint(BinaryData const & A, 
                                             BinaryData const & Bx,
                                             BinaryData const & By)
{
   CryptoPP::ECP ecp = Get_secp256k1_ECP();
   CryptoPP::Integer intA, intBx, intBy, intCx, intCy;

   intA.Decode( A.getPtr(),  A.getSize(),  UNSIGNED);
   intBx.Decode(Bx.getPtr(), Bx.getSize(), UNSIGNED);
   intBy.Decode(By.getPtr(), By.getSize(), UNSIGNED);

   BTC_ECPOINT B(intBx, intBy);
   BTC_ECPOINT C = ecp.ScalarMultiply(B, intA);

   BinaryData Cbd(64);
   C.x.Encode(Cbd.getPtr(),    32, UNSIGNED);
   C.y.Encode(Cbd.getPtr()+32, 32, UNSIGNED);

   return Cbd;
}

////////////////////////////////////////////////////////////////////////////////
BinaryData CryptoECDSA_1_35::ECAddPoints(BinaryData const & Ax, 
                                    BinaryData const & Ay,
                                    BinaryData const & Bx,
                                    BinaryData const & By)
{
   CryptoPP::ECP ecp = Get_secp256k1_ECP();
   CryptoPP::Integer intAx, intAy, intBx, intBy, intCx, intCy;

   intAx.Decode(Ax.getPtr(), Ax.getSize(), UNSIGNED);
   intAy.Decode(Ay.getPtr(), Ay.getSize(), UNSIGNED);
   intBx.Decode(Bx.getPtr(), Bx.getSize(), UNSIGNED);
   intBy.Decode(By.getPtr(), By.getSize(), UNSIGNED);


   BTC_ECPOINT A(intAx, intAy);
   BTC_ECPOINT B(intBx, intBy);

   BTC_ECPOINT C = ecp.Add(A,B);

   BinaryData Cbd(64);
   C.x.Encode(Cbd.getPtr(),    32, UNSIGNED);
   C.y.Encode(Cbd.getPtr()+32, 32, UNSIGNED);

   return Cbd;
}


////////////////////////////////////////////////////////////////////////////////
BinaryData CryptoECDSA_1_35::ECInverse(BinaryData const & Ax, 
                                  BinaryData const & Ay)
                                  
{
   CryptoPP::ECP & ecp = Get_secp256k1_ECP();
   CryptoPP::Integer intAx, intAy, intCx, intCy;

   intAx.Decode(Ax.getPtr(), Ax.getSize(), UNSIGNED);
   intAy.Decode(Ay.getPtr(), Ay.getSize(), UNSIGNED);

   BTC_ECPOINT A(intAx, intAy);
   BTC_ECPOINT C = ecp.Inverse(A);

   BinaryData Cbd(64);
   C.x.Encode(Cbd.getPtr(),    32, UNSIGNED);
   C.y.Encode(Cbd.getPtr()+32, 32, UNSIGNED);

   return Cbd;
}


////////////////////////////////////////////////////////////////////////////////
SecureBinaryData_1_35 CryptoECDSA_1_35::CompressPoint(SecureBinaryData_1_35 const & pubKey65)
{
   CryptoPP::ECP & ecp = Get_secp256k1_ECP();
   BTC_ECPOINT ptPub;
   ecp.DecodePoint(ptPub, (byte*)pubKey65.getPtr(), 65);
   SecureBinaryData_1_35 ptCompressed(33);
   ecp.EncodePoint((byte*)ptCompressed.getPtr(), ptPub, true);
   return ptCompressed; 
}

////////////////////////////////////////////////////////////////////////////////
SecureBinaryData_1_35 CryptoECDSA_1_35::UncompressPoint(SecureBinaryData_1_35 const & pubKey33)
{
   CryptoPP::ECP & ecp = Get_secp256k1_ECP();
   BTC_ECPOINT ptPub;
   ecp.DecodePoint(ptPub, (byte*)pubKey33.getPtr(), 33);
   SecureBinaryData_1_35 ptUncompressed(65);
   ecp.EncodePoint((byte*)ptUncompressed.getPtr(), ptPub, false);
   return ptUncompressed; 

}












   /* OpenSSL code (untested)
   static SecureBinaryData_1_35 sigSpace(1000);
   static uint32_t sigSize = 0;

   // Create the key object
   EC_KEY* pubKey = EC_KEY_new_by_curve_name(NID_secp256k1);

   uint8_t* pbegin = privKey.getPtr();
   d2i_ECPrivateKey(&pubKey, &pbegin, privKey.getSize());

   ECDSA_sign(0, binToSign.getPtr(), 
                 binToSign.getSize(), 
                 sigSpace.getPtr(), 
                 &sigSize, 
                 pubKey)

   EC_KEY_free(pubKey);
   return SecureBinaryData_1_35(sigSpace.getPtr(), sigSize);
   */









