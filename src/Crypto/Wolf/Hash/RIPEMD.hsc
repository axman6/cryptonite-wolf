{-# LANGUAGE DataKinds       #-}
{-# LANGUAGE EmptyDataDecls  #-}
{-# LANGUAGE QuasiQuotes     #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeFamilies    #-}


module Crypto.Wolf.Hash.RIPEMD () where

import           Crypto.Hash.IO
import qualified Data.ByteString           as BS
import           Data.Monoid               ((<>))
import           Foreign.C.Types
import qualified Language.C.Inline         as C
import qualified Language.C.Inline.Unsafe  as CU
import           Data.Word (Word8, Word32)

import           Crypto.Wolf.Hash.Internal
import           Crypto.Wolf.Hash.Types

C.context (C.baseCtx <> C.fptrCtx <> wolfCryptCtx)

#define WC_NO_HARDEN 1
#define WOLFSSL_RIPEMD

C.include "<wolfssl/wolfcrypt/ripemd.h>" 
#include <wolfssl/wolfcrypt/ripemd.h>

instance HashAlgorithm RIPEMD160 where
  type HashBlockSize           RIPEMD160 = 64
  type HashDigestSize          RIPEMD160 = 20
  type HashInternalContextSize RIPEMD160 = (#size RipeMd)
  hashBlockSize  _          = 128
  hashDigestSize _          = 20
  hashInternalContextSize _ = (#size RipeMd)
  hashInternalInit = hInit $ \fctx -> [CU.exp|
    int{ wc_InitRipeMd( $fptr-ptr:(RipeMd *fctx))}
    |]

  hashInternalUpdate = hUpdate $ \fctx fptr n32 -> [CU.exp| 
    int{ wc_RipeMdUpdate( $fptr-ptr:(RipeMd *fctx) , $fptr-ptr:(byte *fptr) , $(word32 n32) ) }
    |]

  hashInternalFinalize = hFinalise $ \fctx fdig -> [CU.exp|
    int{ wc_RipeMdFinal( $fptr-ptr:(RipeMd *fctx) , $fptr-ptr:(byte *fdig) ) } 
    |]
