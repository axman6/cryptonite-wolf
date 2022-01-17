{-# LANGUAGE DataKinds       #-}
{-# LANGUAGE EmptyDataDecls  #-}
{-# LANGUAGE QuasiQuotes     #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeFamilies    #-}
{-# LANGUAGE CPP    #-}
{-# LANGUAGE CApiFFI    #-}
-- {-# LANGUAGE CApiFFI    #-}
{-# OPTIONS_GHC -Wno-orphans -Wall #-}


module Crypto.Wolf.Hash.SHA3
  ( SHA3_224(..)
  , SHA3_256(..)
  , SHA3_384(..)
  , SHA3_512(..)
  ) where

import           Crypto.Hash (Context)
import           Crypto.Hash.IO
import           Control.Monad (void)
import           Foreign.C.Types
import           Foreign.Ptr (Ptr, castPtr, nullPtr)

#include <wolfssl/wolfcrypt/hash.h>


data SHA3_224 = SHA3_224 deriving (Show)
data SHA3_256 = SHA3_256 deriving (Show)
data SHA3_384 = SHA3_384 deriving (Show)
data SHA3_512 = SHA3_512 deriving (Show)


instance HashAlgorithm SHA3_224 where
  type HashBlockSize           SHA3_224 = 144
  type HashDigestSize          SHA3_224 = 28
  type HashInternalContextSize SHA3_224 = {#sizeof wc_Sha3#}

  hashBlockSize  _                    = 144
  hashDigestSize _                    = 28
  hashInternalContextSize _           = {#sizeof wc_Sha3#}

  hashInternalInit ctx                = void $ wc_InitSha3_224 ctx nullPtr 0
  hashInternalUpdate ctx bytes n      = void $ wc_Sha3_224_Update ctx (castPtr bytes) (fromIntegral n)
  hashInternalFinalize ctx digest     = void $ wc_Sha3_224_Final ctx (castPtr digest)


foreign import capi unsafe "wolfssl/wolfcrypt/hash.h wc_InitSha3_224"
  wc_InitSha3_224 :: Ptr (Context SHA3_224) -> Ptr () -> CUInt -> IO CInt

foreign import capi safe "wolfssl/wolfcrypt/hash.h wc_Sha3_224_Update"
  wc_Sha3_224_Update :: Ptr (Context SHA3_224) -> Ptr CUChar -> CUInt -> IO CInt

foreign import capi unsafe "wolfssl/wolfcrypt/hash.h wc_Sha3_224_Final"
  wc_Sha3_224_Final :: Ptr (Context SHA3_224) -> Ptr CUChar -> IO CInt


instance HashAlgorithm SHA3_256 where
  type HashBlockSize           SHA3_256 = 136
  type HashDigestSize          SHA3_256 = 32
  type HashInternalContextSize SHA3_256 = {#sizeof wc_Sha3#}

  hashBlockSize  _                    = 136
  hashDigestSize _                    = 32
  hashInternalContextSize _           = {#sizeof wc_Sha3#}

  hashInternalInit ctx                = void $ wc_InitSha3_256 ctx nullPtr 0
  hashInternalUpdate ctx bytes n      = void $ wc_Sha3_256_Update ctx (castPtr bytes) (fromIntegral n)
  hashInternalFinalize ctx digest     = void $ wc_Sha3_256_Final ctx (castPtr digest)

foreign import capi unsafe "wolfssl/wolfcrypt/hash.h wc_InitSha3_256"
  wc_InitSha3_256 :: Ptr (Context SHA3_256) -> Ptr () -> CUInt -> IO CInt

foreign import capi safe "wolfssl/wolfcrypt/hash.h wc_Sha3_256_Update"
  wc_Sha3_256_Update :: Ptr (Context SHA3_256) -> Ptr CUChar -> CUInt -> IO CInt

foreign import capi unsafe "wolfssl/wolfcrypt/hash.h wc_Sha3_256_Final"
  wc_Sha3_256_Final :: Ptr (Context SHA3_256) -> Ptr CUChar -> IO CInt


instance HashAlgorithm SHA3_384 where
  type HashBlockSize           SHA3_384 = 104
  type HashDigestSize          SHA3_384 = 48
  type HashInternalContextSize SHA3_384 = {#sizeof wc_Sha3#}

  hashBlockSize  _                    = 104
  hashDigestSize _                    = 48
  hashInternalContextSize _           = {#sizeof wc_Sha3#}

  hashInternalInit ctx                = void $ wc_InitSha3_384 ctx nullPtr 0
  hashInternalUpdate ctx bytes n      = void $ wc_Sha3_384_Update ctx (castPtr bytes) (fromIntegral n)
  hashInternalFinalize ctx digest     = void $ wc_Sha3_384_Final ctx (castPtr digest)


foreign import capi unsafe "wolfssl/wolfcrypt/hash.h wc_InitSha3_384"
  wc_InitSha3_384 :: Ptr (Context SHA3_384) -> Ptr () -> CUInt -> IO CInt

foreign import capi safe "wolfssl/wolfcrypt/hash.h wc_Sha3_384_Update"
  wc_Sha3_384_Update :: Ptr (Context SHA3_384) -> Ptr CUChar -> CUInt -> IO CInt

foreign import capi unsafe "wolfssl/wolfcrypt/hash.h wc_Sha3_384_Final"
  wc_Sha3_384_Final :: Ptr (Context SHA3_384) -> Ptr CUChar -> IO CInt

instance HashAlgorithm SHA3_512 where
  type HashBlockSize           SHA3_512 = 72
  type HashDigestSize          SHA3_512 = 64
  type HashInternalContextSize SHA3_512 = {#sizeof wc_Sha3#}

  hashBlockSize  _                    = 72
  hashDigestSize _                    = 64
  hashInternalContextSize _           = {#sizeof wc_Sha3#}

  hashInternalInit ctx                = void $ wc_InitSha3_512 ctx nullPtr 0
  hashInternalUpdate ctx bytes n      = void $ wc_Sha3_512_Update ctx (castPtr bytes) (fromIntegral n)
  hashInternalFinalize ctx digest     = void $ wc_Sha3_512_Final ctx (castPtr digest)


foreign import capi unsafe "wolfssl/wolfcrypt/hash.h wc_InitSha3_512"
  wc_InitSha3_512 :: Ptr (Context SHA3_512) -> Ptr () -> CUInt -> IO CInt

foreign import capi safe "wolfssl/wolfcrypt/hash.h wc_Sha3_512_Update"
  wc_Sha3_512_Update :: Ptr (Context SHA3_512) -> Ptr CUChar -> CUInt -> IO CInt

foreign import capi unsafe "wolfssl/wolfcrypt/hash.h wc_Sha3_512_Final"
  wc_Sha3_512_Final :: Ptr (Context SHA3_512) -> Ptr CUChar -> IO CInt

