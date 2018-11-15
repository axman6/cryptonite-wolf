{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications    #-}

module Main where

import           Criterion.Main

import           Control.Monad        (replicateM)
import qualified Crypto.Hash          as Hash
import           Crypto.Random
import           Crypto.Wolf.Hash
import qualified Data.ByteString      as S
import qualified Data.ByteString.Lazy as L



main :: IO ()
main = do
  rand1M <- getRandomBytes (5*1048576) :: IO S.ByteString
  lrand1M <- L.fromChunks <$> replicateM (5*32) (getRandomBytes (32*1024 - 16))
  let benchFor :: forall a b. (HashAlgorithm a, HashAlgorithm b, Show a)
               => a -> b -> Benchmark
      benchFor a _b =
        bgroup (show a)
          [ bench "Strict/Wolf"  $ nf (hash @_ @a) rand1M
          , bench "Strict/Cryptonite"  $ nf (hash @_ @b) rand1M
          , bench "Lazy/Wolf"  $ nf (hashlazy @a) lrand1M
          , bench "Lazy/Cryptonite"  $ nf (hashlazy @b) lrand1M
          ]
  defaultMain [
    bgroup "Hash"
      [ benchFor SHA1        Hash.SHA1
      , benchFor SHA224      Hash.SHA224
      , benchFor SHA256      Hash.SHA256
      , benchFor SHA384      Hash.SHA384
      , benchFor SHA512      Hash.SHA512
      , benchFor SHA3_224    Hash.SHA3_224
      , benchFor SHA3_256    Hash.SHA3_256
      , benchFor SHA3_384    Hash.SHA3_384
      , benchFor SHA3_512    Hash.SHA3_512
      , benchFor Blake2b_160 Hash.Blake2b_160
      , benchFor Blake2b_224 Hash.Blake2b_224
      , benchFor Blake2b_256 Hash.Blake2b_256
      , benchFor Blake2b_384 Hash.Blake2b_384
      , benchFor Blake2b_512 Hash.Blake2b_512
      , benchFor RIPEMD160   Hash.RIPEMD160
      ]
    ]
