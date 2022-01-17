{-# LANGUAGE DataKinds       #-}
{-# LANGUAGE EmptyDataDecls  #-}
{-# LANGUAGE QuasiQuotes     #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeFamilies    #-}
{-# LANGUAGE CApiFFI         #-}
{-# OPTIONS_GHC -Wno-orphans #-}



module Crypto.Wolf.Hash.RIPEMD (RIPEMD160(..)) where

import           Crypto.Hash (Context)
import           Crypto.Hash.IO
import           Control.Monad (void)
import           Foreign.C.Types
import           Foreign.Ptr (Ptr, castPtr)

#include <wolfssl/wolfcrypt/ripemd.h>

data RIPEMD160 = RIPEMD160 deriving (Show)

instance HashAlgorithm RIPEMD160 where
  type HashBlockSize           RIPEMD160 = 64
  type HashDigestSize          RIPEMD160 = 20
  type HashInternalContextSize RIPEMD160 = {#sizeof RipeMd#}

  hashBlockSize  _                    = 64
  hashDigestSize _                    = 20
  hashInternalContextSize _           = {#sizeof RipeMd#}

  hashInternalInit ctx                = void $ wc_InitRipeMd ctx
  hashInternalUpdate ctx bytes n      = void $ wc_RipeMdUpdate ctx (castPtr bytes) (fromIntegral n)
  hashInternalFinalize ctx digest     = void $ wc_RipeMdFinal ctx (castPtr digest)


foreign import capi unsafe "wolfssl/wolfcrypt/ripemd.h wc_InitRipeMd"
  wc_InitRipeMd :: Ptr (Context RIPEMD160) -> IO CInt

foreign import capi safe "wolfssl/wolfcrypt/ripemd.h wc_RipeMdUpdate"
  wc_RipeMdUpdate :: Ptr (Context RIPEMD160) -> Ptr CUChar -> CUInt -> IO CInt

foreign import capi unsafe "wolfssl/wolfcrypt/ripemd.h wc_RipeMdFinal"
  wc_RipeMdFinal :: Ptr (Context RIPEMD160) -> Ptr CUChar -> IO CInt
