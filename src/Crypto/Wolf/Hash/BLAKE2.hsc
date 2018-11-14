{-# LANGUAGE DataKinds                #-}
{-# LANGUAGE EmptyDataDecls           #-}
{-# LANGUAGE QuasiQuotes              #-}
{-# LANGUAGE TemplateHaskell          #-}
{-# LANGUAGE TypeFamilies             #-}
{-# LANGUAGE TypeOperators            #-}
{-# LANGUAGE UndecidableInstances     #-}
{-# LANGUAGE BangPatterns             #-}
{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE TupleSections            #-}
{-# OPTIONS_GHC -Wno-orphans          #-}



module Crypto.Wolf.Hash.BLAKE2 () where

import           Crypto.Hash.IO
import           Data.Monoid               ((<>))
import           Foreign.C.Types
import qualified Language.C.Inline         as C
import qualified Language.C.Inline.Unsafe  as CU

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



{-
================================================================================
  Special notes
================================================================================
  It appears that GHC/c2hs/inline-c/something else doesn't know about the
  required alignment for the Blake2b struct, which was causing memory corruption
  issues in the original code, which looked similar to the implementation of the
  other hash algorithms. This is why this module uses CU.block, and copies the
  hash state from the given pointer, passes that reference to the Blake2b
  functions, and then copies the result back.

-}


instance HashAlgorithm Blake2b_160 where
  type HashBlockSize           Blake2b_160 = (#const BLAKE2B_BLOCKBYTES)
  type HashDigestSize          Blake2b_160 = 20
  type HashInternalContextSize Blake2b_160 = (#size Blake2b)
  hashBlockSize  _          = (#const BLAKE2B_BLOCKBYTES)
  hashDigestSize _          = 20
  hashInternalContextSize _ = (#size Blake2b)
  hashInternalInit = hInit $ \fctx -> let n = 160 `div` 8 in [CU.block|
    int{ 
      Blake2b stat = *((Blake2b *)$fptr-ptr:(hs_BLAKE2_160 *fctx));
      // printf("wc_InitBlake2b(%p, %u)\n",$fptr-ptr:(hs_BLAKE2_160 *fctx), $(word32 n)); 
      int ret = wc_InitBlake2b( &stat, $(word32 n));
      *((Blake2b *)$fptr-ptr:(hs_BLAKE2_160 *fctx)) = stat;
      return ret;
      }
    |]

  hashInternalUpdate = hUpdate $ \fctx fptr n32 ->  [CU.block|
    int{ // printf("wc_Blake2bUpdate(%p, %p, %u)\n",$fptr-ptr:(hs_BLAKE2_160 *fctx), $fptr-ptr:(byte *fptr), $(word32 n32));
      Blake2b stat = *((Blake2b *)$fptr-ptr:(hs_BLAKE2_160 *fctx));
      int ret=  wc_Blake2bUpdate( &stat , $fptr-ptr:(byte *fptr) , $(word32 n32) ); 
      *((Blake2b *)$fptr-ptr:(hs_BLAKE2_160 *fctx)) = stat;
      return ret;
      }
      |]
      -- return wc_Blake2bUpdate( $fptr-ptr:(hs_BLAKE2_160 *fctx) , $fptr-ptr:(byte *fptr) , $(word32 n32) ); 

  hashInternalFinalize = hFinalise $ \fctx fdig -> let n = 160 `div` 8 in [CU.block|
    int{ 
      Blake2b stat = *((Blake2b *)$fptr-ptr:(hs_BLAKE2_160 *fctx));
      // printf("wc_Blake2bFinal(%p(%p), %u)\n",$fptr-ptr:(hs_BLAKE2_160 *fctx), &stat, $(word32 n)); 
      int ret = wc_Blake2bFinal( &stat , $fptr-ptr:(byte *fdig) , $(word32 n)); 
      *((Blake2b *)$fptr-ptr:(hs_BLAKE2_160 *fctx)) = stat;
      return ret;
      } 
    |]



instance HashAlgorithm Blake2b_224 where
  type HashBlockSize           Blake2b_224 = (#const BLAKE2B_BLOCKBYTES)
  type HashDigestSize          Blake2b_224 = 28
  type HashInternalContextSize Blake2b_224 = (#size Blake2b)
  hashBlockSize  _          = (#const BLAKE2B_BLOCKBYTES)
  hashDigestSize _          = 28
  hashInternalContextSize _ = (#size Blake2b)
  hashInternalInit = hInit $ \fctx -> let n = 224 `div` 8 in [CU.block|
    int{ 
      Blake2b stat = *((Blake2b *)$fptr-ptr:(hs_BLAKE2_224 *fctx));
      // printf("wc_InitBlake2b(%p, %u)\n",$fptr-ptr:(hs_BLAKE2_224 *fctx), $(word32 n)); 
      int ret = wc_InitBlake2b( &stat, $(word32 n));
      *((Blake2b *)$fptr-ptr:(hs_BLAKE2_224 *fctx)) = stat;
      return ret;
      }
    |]

  hashInternalUpdate = hUpdate $ \fctx fptr n32 ->  [CU.block|
    int{ // printf("wc_Blake2bUpdate(%p, %p, %u)\n",$fptr-ptr:(hs_BLAKE2_224 *fctx), $fptr-ptr:(byte *fptr), $(word32 n32));
      Blake2b stat = *((Blake2b *)$fptr-ptr:(hs_BLAKE2_224 *fctx));
      int ret=  wc_Blake2bUpdate( &stat , $fptr-ptr:(byte *fptr) , $(word32 n32) ); 
      *((Blake2b *)$fptr-ptr:(hs_BLAKE2_224 *fctx)) = stat;
      return ret;
      }
      |]
      -- return wc_Blake2bUpdate( $fptr-ptr:(hs_BLAKE2_224 *fctx) , $fptr-ptr:(byte *fptr) , $(word32 n32) ); 

  hashInternalFinalize = hFinalise $ \fctx fdig -> let n = 224 `div` 8 in [CU.block|
    int{ 
      Blake2b stat = *((Blake2b *)$fptr-ptr:(hs_BLAKE2_224 *fctx));
      // printf("wc_Blake2bFinal(%p(%p), %u)\n",$fptr-ptr:(hs_BLAKE2_224 *fctx), &stat, $(word32 n)); 
      int ret = wc_Blake2bFinal( &stat , $fptr-ptr:(byte *fdig) , $(word32 n)); 
      *((Blake2b *)$fptr-ptr:(hs_BLAKE2_224 *fctx)) = stat;
      return ret;
      } 
    |]

instance HashAlgorithm Blake2b_256 where
  type HashBlockSize           Blake2b_256 = (#const BLAKE2B_BLOCKBYTES)
  type HashDigestSize          Blake2b_256 = 32
  type HashInternalContextSize Blake2b_256 = (#size Blake2b)
  hashBlockSize  _          = (#const BLAKE2B_BLOCKBYTES)
  hashDigestSize _          = 32
  hashInternalContextSize _ = (#size Blake2b)
  hashInternalInit = hInit $ \fctx -> let n = 256 `div` 8 in [CU.block|
    int{ 
      Blake2b stat = *((Blake2b *)$fptr-ptr:(hs_BLAKE2_256 *fctx));
      // printf("wc_InitBlake2b(%p, %u)\n",$fptr-ptr:(hs_BLAKE2_256 *fctx), $(word32 n)); 
      int ret = wc_InitBlake2b( &stat, $(word32 n));
      *((Blake2b *)$fptr-ptr:(hs_BLAKE2_256 *fctx)) = stat;
      return ret;
      }
    |]

  hashInternalUpdate = hUpdate $ \fctx fptr n32 ->  [CU.block|
    int{ // printf("wc_Blake2bUpdate(%p, %p, %u)\n",$fptr-ptr:(hs_BLAKE2_256 *fctx), $fptr-ptr:(byte *fptr), $(word32 n32));
      Blake2b stat = *((Blake2b *)$fptr-ptr:(hs_BLAKE2_256 *fctx));
      int ret=  wc_Blake2bUpdate( &stat , $fptr-ptr:(byte *fptr) , $(word32 n32) ); 
      *((Blake2b *)$fptr-ptr:(hs_BLAKE2_256 *fctx)) = stat;
      return ret;
      }
      |]
      -- return wc_Blake2bUpdate( $fptr-ptr:(hs_BLAKE2_256 *fctx) , $fptr-ptr:(byte *fptr) , $(word32 n32) ); 

  hashInternalFinalize = hFinalise $ \fctx fdig -> let n = 256 `div` 8 in [CU.block|
    int{ 
      Blake2b stat = *((Blake2b *)$fptr-ptr:(hs_BLAKE2_256 *fctx));
      // printf("wc_Blake2bFinal(%p(%p), %u)\n",$fptr-ptr:(hs_BLAKE2_256 *fctx), &stat, $(word32 n)); 
      int ret = wc_Blake2bFinal( &stat , $fptr-ptr:(byte *fdig) , $(word32 n)); 
      *((Blake2b *)$fptr-ptr:(hs_BLAKE2_256 *fctx)) = stat;
      return ret;
      } 
    |]

instance HashAlgorithm Blake2b_384 where
  type HashBlockSize           Blake2b_384 = (#const BLAKE2B_BLOCKBYTES)
  type HashDigestSize          Blake2b_384 = 48
  type HashInternalContextSize Blake2b_384 = (#size Blake2b)
  hashBlockSize  _          = (#const BLAKE2B_BLOCKBYTES)
  hashDigestSize _          = 48
  hashInternalContextSize _ = (#size Blake2b)
  hashInternalInit = hInit $ \fctx -> let n = 384 `div` 8 in [CU.block|
    int{ 
      Blake2b stat = *((Blake2b *)$fptr-ptr:(hs_BLAKE2_384 *fctx));
      // printf("wc_InitBlake2b(%p, %u)\n",$fptr-ptr:(hs_BLAKE2_384 *fctx), $(word32 n)); 
      int ret = wc_InitBlake2b( &stat, $(word32 n));
      *((Blake2b *)$fptr-ptr:(hs_BLAKE2_384 *fctx)) = stat;
      return ret;
      }
    |]

  hashInternalUpdate = hUpdate $ \fctx fptr n32 ->  [CU.block|
    int{ // printf("wc_Blake2bUpdate(%p, %p, %u)\n",$fptr-ptr:(hs_BLAKE2_384 *fctx), $fptr-ptr:(byte *fptr), $(word32 n32));
      Blake2b stat = *((Blake2b *)$fptr-ptr:(hs_BLAKE2_384 *fctx));
      int ret=  wc_Blake2bUpdate( &stat , $fptr-ptr:(byte *fptr) , $(word32 n32) ); 
      *((Blake2b *)$fptr-ptr:(hs_BLAKE2_384 *fctx)) = stat;
      return ret;
      }
      |]
      -- return wc_Blake2bUpdate( $fptr-ptr:(hs_BLAKE2_384 *fctx) , $fptr-ptr:(byte *fptr) , $(word32 n32) ); 

  hashInternalFinalize = hFinalise $ \fctx fdig -> let n = 384 `div` 8 in [CU.block|
    int{ 
      Blake2b stat = *((Blake2b *)$fptr-ptr:(hs_BLAKE2_384 *fctx));
      // printf("wc_Blake2bFinal(%p(%p), %u)\n",$fptr-ptr:(hs_BLAKE2_384 *fctx), &stat, $(word32 n)); 
      int ret = wc_Blake2bFinal( &stat , $fptr-ptr:(byte *fdig) , $(word32 n)); 
      *((Blake2b *)$fptr-ptr:(hs_BLAKE2_384 *fctx)) = stat;
      return ret;
      } 
    |]


instance HashAlgorithm Blake2b_512 where
  type HashBlockSize           Blake2b_512 = (#const BLAKE2B_BLOCKBYTES)
  type HashDigestSize          Blake2b_512 = 64
  type HashInternalContextSize Blake2b_512 = (#size Blake2b)
  hashBlockSize  _          = (#const BLAKE2B_BLOCKBYTES)
  hashDigestSize _          = 64
  hashInternalContextSize _ = (#size Blake2b)
  hashInternalInit = hInit $ \fctx -> let n = 512 `div` 8 in [CU.block|
    int{ 
      Blake2b stat = *((Blake2b *)$fptr-ptr:(hs_BLAKE2_512 *fctx));
      // printf("wc_InitBlake2b(%p, %u)\n",$fptr-ptr:(hs_BLAKE2_512 *fctx), $(word32 n)); 
      int ret = wc_InitBlake2b( &stat, $(word32 n));
      *((Blake2b *)$fptr-ptr:(hs_BLAKE2_512 *fctx)) = stat;
      return ret;
      }
    |]

  hashInternalUpdate = hUpdate $ \fctx fptr n32 ->  [CU.block|
    int{ // printf("wc_Blake2bUpdate(%p, %p, %u)\n",$fptr-ptr:(hs_BLAKE2_512 *fctx), $fptr-ptr:(byte *fptr), $(word32 n32));
      Blake2b stat = *((Blake2b *)$fptr-ptr:(hs_BLAKE2_512 *fctx));
      int ret=  wc_Blake2bUpdate( &stat , $fptr-ptr:(byte *fptr) , $(word32 n32) ); 
      *((Blake2b *)$fptr-ptr:(hs_BLAKE2_512 *fctx)) = stat;
      return ret;
      }
      |]
      -- return wc_Blake2bUpdate( $fptr-ptr:(hs_BLAKE2_512 *fctx) , $fptr-ptr:(byte *fptr) , $(word32 n32) ); 

  hashInternalFinalize = hFinalise $ \fctx fdig -> let n = 512 `div` 8 in [CU.block|
    int{ 
      Blake2b stat = *((Blake2b *)$fptr-ptr:(hs_BLAKE2_512 *fctx));
      // printf("wc_Blake2bFinal(%p(%p), %u)\n",$fptr-ptr:(hs_BLAKE2_512 *fctx), &stat, $(word32 n)); 
      int ret = wc_Blake2bFinal( &stat , $fptr-ptr:(byte *fdig) , $(word32 n)); 
      *((Blake2b *)$fptr-ptr:(hs_BLAKE2_512 *fctx)) = stat;
      return ret;
      } 
    |]

