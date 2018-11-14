{-# LANGUAGE CPP                 #-}
{-# LANGUAGE RankNTypes          #-}
{-# LANGUAGE ScopedTypeVariables #-}


module Spec where


import           Test.Tasty.QuickCheck

import           Data.ByteArray
import qualified Data.ByteString                      as S
import qualified Data.ByteString.Lazy                 as L
import           Test.QuickCheck.Instances.ByteString ()

import qualified Crypto.Hash                          as Hash
import           Crypto.Wolf.Hash

hsh :: HashAlgorithm a => a -> S.ByteString -> Digest a
hsh _ = hash

hshL :: HashAlgorithm a => a -> L.ByteString -> Digest a
hshL _ = hashlazy

testAlg :: (HashAlgorithm a, HashAlgorithm b) => a -> b -> S.ByteString -> Bool
testAlg a b bs = eq (hsh a bs) (hsh b bs)

testAlgLazy :: (HashAlgorithm a, HashAlgorithm b) => a -> b -> L.ByteString -> Bool
testAlgLazy a b bs = eq (hshL a bs) (hshL b bs)

prop_SHA1             = testAlg     SHA1 Hash.SHA1
prop_SHA1_Lazy        = testAlgLazy SHA1 Hash.SHA1

prop_SHA224           = testAlg     SHA224 Hash.SHA224
prop_SHA224_Lazy      = testAlgLazy SHA224 Hash.SHA224
prop_SHA256           = testAlg     SHA256 Hash.SHA256
prop_SHA256_Lazy      = testAlgLazy SHA256 Hash.SHA256
prop_SHA384           = testAlg     SHA384 Hash.SHA384
prop_SHA384_Lazy      = testAlgLazy SHA384 Hash.SHA384
prop_SHA512           = testAlg     SHA512 Hash.SHA512
prop_SHA512_Lazy      = testAlgLazy SHA512 Hash.SHA512

prop_SHA3_224         = testAlg     SHA3_224 Hash.SHA3_224
prop_SHA3_224_Lazy    = testAlgLazy SHA3_224 Hash.SHA3_224
prop_SHA3_256         = testAlg     SHA3_256 Hash.SHA3_256
prop_SHA3_256_Lazy    = testAlgLazy SHA3_256 Hash.SHA3_256
prop_SHA3_384         = testAlg     SHA3_384 Hash.SHA3_384
prop_SHA3_384_Lazy    = testAlgLazy SHA3_384 Hash.SHA3_384
prop_SHA3_512         = testAlg     SHA3_512 Hash.SHA3_512
prop_SHA3_512_Lazy    = testAlgLazy SHA3_512 Hash.SHA3_512

prop_RIPEMD160        = testAlg     RIPEMD160 Hash.RIPEMD160
prop_RIPEMD160_Lazy   = testAlgLazy RIPEMD160 Hash.RIPEMD160

prop_Blake2b_160      = testAlg     Blake2b_160 Hash.Blake2b_160
prop_Blake2b_160_Lazy = testAlgLazy Blake2b_160 Hash.Blake2b_160
prop_Blake2b_224      = testAlg     Blake2b_224 Hash.Blake2b_224
prop_Blake2b_224_Lazy = testAlgLazy Blake2b_224 Hash.Blake2b_224
prop_Blake2b_256      = testAlg     Blake2b_256 Hash.Blake2b_256
prop_Blake2b_256_Lazy = testAlgLazy Blake2b_256 Hash.Blake2b_256
prop_Blake2b_384      = testAlg     Blake2b_384 Hash.Blake2b_384
prop_Blake2b_384_Lazy = testAlgLazy Blake2b_384 Hash.Blake2b_384
prop_Blake2b_512      = testAlg     Blake2b_512 Hash.Blake2b_512
prop_Blake2b_512_Lazy = testAlgLazy Blake2b_512 Hash.Blake2b_512
--
