{-# LANGUAGE DataKinds       #-}
{-# LANGUAGE EmptyDataDecls  #-}
{-# LANGUAGE QuasiQuotes     #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeFamilies    #-}


module Crypto.Wolf.Hash.BLAKE2 () where

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
#define HAVE_BLAKE2


#define hs_BLAKE2_160 Blake2b
#define hs_BLAKE2_224 Blake2b
#define hs_BLAKE2_256 Blake2b
#define hs_BLAKE2_384 Blake2b
#define hs_BLAKE2_512 Blake2b

C.include "<wolfssl/wolfcrypt/hash.h>" 
#include <wolfssl/wolfcrypt/hash.h>

instance HashAlgorithm Blake2b_160 where
  type HashBlockSize           Blake2b_160 = 128
  type HashDigestSize          Blake2b_160 = 20
  type HashInternalContextSize Blake2b_160 = (#size Blake2b)
  hashBlockSize  _          = 128
  hashDigestSize _          = 20
  hashInternalContextSize _ = (#size Blake2b)
  hashInternalInit = hInit $ \fctx -> [CU.exp|
    int{ wc_InitBlake2b( $fptr-ptr:(hs_BLAKE2_160 *fctx), 160 / 8)}
    |]

  hashInternalUpdate = hUpdate $ \fctx fptr n32 -> [CU.exp| 
    int{ wc_Blake2bUpdate( $fptr-ptr:(hs_BLAKE2_160 *fctx) , $fptr-ptr:(byte *fptr) , $(word32 n32) ) }
    |]

  hashInternalFinalize = hFinalise $ \fctx fdig -> [CU.exp|
    int{ wc_Blake2bFinal( $fptr-ptr:(hs_BLAKE2_160 *fctx) , $fptr-ptr:(byte *fdig) , 160 / 8) } 
    |]

instance HashAlgorithm Blake2b_224 where
  type HashBlockSize           Blake2b_224 = 128
  type HashDigestSize          Blake2b_224 = 28
  type HashInternalContextSize Blake2b_224 = (#size Blake2b)
  hashBlockSize  _          = 128
  hashDigestSize _          = 28
  hashInternalContextSize _ = (#size Blake2b)
  hashInternalInit = hInit $ \fctx -> [CU.exp|
    int{ wc_InitBlake2b( $fptr-ptr:(hs_BLAKE2_224 *fctx), 224 / 8)}
    |]

  hashInternalUpdate = hUpdate $ \fctx fptr n32 -> [CU.exp| 
    int{ wc_Blake2bUpdate( $fptr-ptr:(hs_BLAKE2_224 *fctx) , $fptr-ptr:(byte *fptr) , $(word32 n32) ) }
    |]

  hashInternalFinalize = hFinalise $ \fctx fdig -> [CU.exp|
    int{ wc_Blake2bFinal( $fptr-ptr:(hs_BLAKE2_224 *fctx) , $fptr-ptr:(byte *fdig) , 224 / 8) } 
    |]

instance HashAlgorithm Blake2b_256 where
  type HashBlockSize           Blake2b_256 = 128
  type HashDigestSize          Blake2b_256 = 32
  type HashInternalContextSize Blake2b_256 = (#size Blake2b)
  hashBlockSize  _          = 128
  hashDigestSize _          = 32
  hashInternalContextSize _ = (#size Blake2b)
  hashInternalInit = hInit $ \fctx -> [CU.exp|
    int{ wc_InitBlake2b( $fptr-ptr:(hs_BLAKE2_256 *fctx), 256 / 8)}
    |]

  hashInternalUpdate = hUpdate $ \fctx fptr n32 -> [CU.exp| 
    int{ wc_Blake2bUpdate( $fptr-ptr:(hs_BLAKE2_256 *fctx) , $fptr-ptr:(byte *fptr) , $(word32 n32) ) }
    |]

  hashInternalFinalize = hFinalise $ \fctx fdig -> [CU.exp|
    int{ wc_Blake2bFinal( $fptr-ptr:(hs_BLAKE2_256 *fctx) , $fptr-ptr:(byte *fdig) , 256 / 8) } 
    |]

instance HashAlgorithm Blake2b_384 where
  type HashBlockSize           Blake2b_384 = 128
  type HashDigestSize          Blake2b_384 = 48
  type HashInternalContextSize Blake2b_384 = (#size Blake2b)
  hashBlockSize  _          = 128
  hashDigestSize _          = 48
  hashInternalContextSize _ = (#size Blake2b)
  hashInternalInit = hInit $ \fctx -> [CU.exp|
    int{ wc_InitBlake2b( $fptr-ptr:(hs_BLAKE2_384 *fctx), 384 / 8)}
    |]

  hashInternalUpdate = hUpdate $ \fctx fptr n32 -> [CU.exp| 
    int{ wc_Blake2bUpdate( $fptr-ptr:(hs_BLAKE2_384 *fctx) , $fptr-ptr:(byte *fptr) , $(word32 n32) ) }
    |]

  hashInternalFinalize = hFinalise $ \fctx fdig -> [CU.exp|
    int{ wc_Blake2bFinal( $fptr-ptr:(hs_BLAKE2_384 *fctx) , $fptr-ptr:(byte *fdig) , 384 / 8) } 
    |]


instance HashAlgorithm Blake2b_512 where
  type HashBlockSize           Blake2b_512 = 128
  type HashDigestSize          Blake2b_512 = 64
  type HashInternalContextSize Blake2b_512 = (#size Blake2b)
  hashBlockSize  _          = 128
  hashDigestSize _          = 64
  hashInternalContextSize _ = (#size Blake2b)
  hashInternalInit = hInit $ \fctx -> [CU.exp|
    int{ wc_InitBlake2b( $fptr-ptr:(hs_BLAKE2_512 *fctx), 512 / 8)}
    |]

  hashInternalUpdate = hUpdate $ \fctx fptr n32 -> [CU.exp| 
    int{ wc_Blake2bUpdate( $fptr-ptr:(hs_BLAKE2_512 *fctx) , $fptr-ptr:(byte *fptr) , $(word32 n32) ) }
    |]

  hashInternalFinalize = hFinalise $ \fctx fdig -> [CU.exp|
    int{ wc_Blake2bFinal( $fptr-ptr:(hs_BLAKE2_512 *fctx) , $fptr-ptr:(byte *fdig) , 512 / 8) } 
    |]
