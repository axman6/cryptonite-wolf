{-# LANGUAGE DataKinds       #-}
{-# LANGUAGE EmptyDataDecls  #-}
{-# LANGUAGE QuasiQuotes     #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeFamilies    #-}
{-# LANGUAGE CPP             #-}
{-# LANGUAGE CApiFFI         #-}
{-# OPTIONS_GHC -Wno-orphans -Wall #-}


module Crypto.Wolf.Hash.SHA
  ( SHA1(..)
  , SHA224(..)
  , SHA256(..)
  , SHA384(..)
  , SHA512(..)
  ) where

import           Crypto.Hash (Context)
import           Crypto.Hash.IO
import           Control.Monad (void)
import           Foreign.C.Types
import           Foreign.Ptr (Ptr, castPtr)

#define WOLFSSL_SHA224

-- #include <wolfssl/config.h>
#include <wolfssl/wolfcrypt/hash.h>


data SHA1 = SHA1 deriving (Show)
data SHA224 = SHA224 deriving (Show)
data SHA256 = SHA256 deriving (Show)
data SHA384 = SHA384 deriving (Show)
data SHA512 = SHA512 deriving (Show)


instance HashAlgorithm SHA1 where
  type HashBlockSize           SHA1 = 64 -- WC_SHA_BLOCK_SIZE
  type HashDigestSize          SHA1 = 20 -- WC_SHA_DIGEST_SIZE
  type HashInternalContextSize SHA1 = {#sizeof wc_Sha#}

  hashBlockSize  _                  = 64 -- WC_SHA_BLOCK_SIZE
  hashDigestSize _                  = 20 -- WC_SHA_DIGEST_SIZE
  hashInternalContextSize _         = {#sizeof wc_Sha#}

  hashInternalInit ctx              = void $ wc_InitSha ctx
  hashInternalUpdate ctx bytes n    = void $ wc_ShaUpdate ctx (castPtr bytes) (fromIntegral n)
  hashInternalFinalize ctx digest   = void $ wc_ShaFinal ctx (castPtr digest)


foreign import capi unsafe "wolfssl/wolfcrypt/hash.h wc_InitSha"
  wc_InitSha :: Ptr (Context SHA1) -> IO CInt

foreign import capi safe "wolfssl/wolfcrypt/hash.h wc_ShaUpdate"
  wc_ShaUpdate :: Ptr (Context SHA1) -> Ptr CUChar -> CUInt -> IO CInt

foreign import capi unsafe "wolfssl/wolfcrypt/hash.h wc_ShaFinal"
  wc_ShaFinal :: Ptr (Context SHA1) -> Ptr CUChar -> IO CInt




instance HashAlgorithm SHA224 where
  type HashBlockSize           SHA224 = 64 -- {#const WC_SHA224_BLOCK_SIZE #}
  type HashDigestSize          SHA224 = 28 -- {#const WC_SHA224_DIGEST_SIZE #}
  type HashInternalContextSize SHA224 = {#sizeof wc_Sha224#}

  hashBlockSize  _                    = 64 -- {#const WC_SHA224_BLOCK_SIZE #}
  hashDigestSize _                    = 28 -- {#const WC_SHA224_DIGEST_SIZE #}
  hashInternalContextSize _           = {#sizeof wc_Sha224#}

  hashInternalUpdate ctx bytes n      = void $ wc_Sha224Update ctx (castPtr bytes) (fromIntegral n)
  hashInternalInit ctx                = void $ wc_InitSha224 ctx
  hashInternalFinalize ctx digest     = void $ wc_Sha224Final ctx (castPtr digest)


foreign import capi unsafe "wolfssl/wolfcrypt/hash.h wc_InitSha224"
  wc_InitSha224 :: Ptr (Context SHA224) -> IO CInt

foreign import capi safe "wolfssl/wolfcrypt/hash.h wc_Sha224Update"
  wc_Sha224Update :: Ptr (Context SHA224) -> Ptr CUChar -> CUInt -> IO CInt

foreign import capi unsafe "wolfssl/wolfcrypt/hash.h wc_Sha224Final"
  wc_Sha224Final :: Ptr (Context SHA224) -> Ptr CUChar -> IO CInt


instance HashAlgorithm SHA256 where
  type HashBlockSize           SHA256 = 64 -- {#const WC_SHA256_BLOCK_SIZE #}
  type HashDigestSize          SHA256 = 32 -- {#const WC_SHA256_DIGEST_SIZE #}
  type HashInternalContextSize SHA256 = {#sizeof wc_Sha256#}

  hashBlockSize  _                    = 64 -- {#const WC_SHA256_BLOCK_SIZE #}
  hashDigestSize _                    = 32 -- {#const WC_SHA256_DIGEST_SIZE #}
  hashInternalContextSize _           = {#sizeof wc_Sha256#}

  hashInternalInit ctx                = void $ wc_InitSha256 ctx
  hashInternalUpdate ctx bytes n      = void $ wc_Sha256Update ctx (castPtr bytes) (fromIntegral n)
  hashInternalFinalize ctx digest     = void $ wc_Sha256Final ctx (castPtr digest)

foreign import capi unsafe "wolfssl/wolfcrypt/hash.h wc_InitSha256"
  wc_InitSha256 :: Ptr (Context SHA256) -> IO CInt

foreign import capi safe "wolfssl/wolfcrypt/hash.h wc_Sha256Update"
  wc_Sha256Update :: Ptr (Context SHA256) -> Ptr CUChar -> CUInt -> IO CInt

foreign import capi unsafe "wolfssl/wolfcrypt/hash.h wc_Sha256Final"
  wc_Sha256Final :: Ptr (Context SHA256) -> Ptr CUChar -> IO CInt


instance HashAlgorithm SHA384 where
  type HashBlockSize           SHA384 = 128 -- {#const WC_SHA384_BLOCK_SIZE #}
  type HashDigestSize          SHA384 = 48 -- {#const WC_SHA384_DIGEST_SIZE #}
  type HashInternalContextSize SHA384 = {#sizeof wc_Sha384#}

  hashBlockSize  _                    = 128 -- {#const WC_SHA384_BLOCK_SIZE #}
  hashDigestSize _                    = 48 -- {#const WC_SHA384_DIGEST_SIZE #}
  hashInternalContextSize _           = {#sizeof wc_Sha384#}

  hashInternalInit ctx                = void $ wc_InitSha384 ctx
  hashInternalUpdate ctx bytes n      = void $ wc_Sha384Update ctx (castPtr bytes) (fromIntegral n)
  hashInternalFinalize ctx digest     = void $ wc_Sha384Final ctx (castPtr digest)


foreign import capi unsafe "wolfssl/wolfcrypt/hash.h wc_InitSha384"
  wc_InitSha384 :: Ptr (Context SHA384) -> IO CInt

foreign import capi safe "wolfssl/wolfcrypt/hash.h wc_Sha384Update"
  wc_Sha384Update :: Ptr (Context SHA384) -> Ptr CUChar -> CUInt -> IO CInt

foreign import capi unsafe "wolfssl/wolfcrypt/hash.h wc_Sha384Final"
  wc_Sha384Final :: Ptr (Context SHA384) -> Ptr CUChar -> IO CInt

instance HashAlgorithm SHA512 where
  type HashBlockSize           SHA512 = 128 -- {#const WC_SHA512_BLOCK_SIZE #}
  type HashDigestSize          SHA512 = 64 -- {#const WC_SHA512_DIGEST_SIZE #}
  type HashInternalContextSize SHA512 = {#sizeof wc_Sha512#}

  hashBlockSize  _                    = 128 -- {#const WC_SHA512_BLOCK_SIZE #}
  hashDigestSize _                    = 64 -- {#const WC_SHA512_DIGEST_SIZE #}
  hashInternalContextSize _           = {#sizeof wc_Sha512#}

  hashInternalInit ctx                = void $ wc_InitSha512 ctx
  hashInternalUpdate ctx bytes n      = void $ wc_Sha512Update ctx (castPtr bytes) (fromIntegral n)
  hashInternalFinalize ctx digest     = void $ wc_Sha512Final ctx (castPtr digest)


foreign import capi unsafe "wolfssl/wolfcrypt/hash.h wc_InitSha512"
  wc_InitSha512 :: Ptr (Context SHA512) -> IO CInt

foreign import capi safe "wolfssl/wolfcrypt/hash.h wc_Sha512Update"
  wc_Sha512Update :: Ptr (Context SHA512) -> Ptr CUChar -> CUInt -> IO CInt

foreign import capi unsafe "wolfssl/wolfcrypt/hash.h wc_Sha512Final"
  wc_Sha512Final :: Ptr (Context SHA512) -> Ptr CUChar -> IO CInt

