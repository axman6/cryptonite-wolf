{-# LANGUAGE DataKinds       #-}
{-# LANGUAGE EmptyDataDecls  #-}
{-# LANGUAGE QuasiQuotes     #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeFamilies    #-}
{-# LANGUAGE CPP             #-}
{-# LANGUAGE CApiFFI         #-}
{-# LANGUAGE BangPatterns         #-}
{-# OPTIONS_GHC -Wno-orphans -Wall #-}



module Crypto.Wolf.Hash.BLAKE2
  ( Blake2b_160(..)
  ) where

import           Crypto.Hash (Context)
import           Crypto.Hash.IO
import           Control.Monad              (void, when)
import           Foreign.C.Types
import           Foreign.Ptr (Ptr, castPtr)
import Foreign.Marshal.Utils (copyBytes)

import Foreign.Marshal.Alloc (allocaBytesAligned)

#define HAVE_BLAKE2

#include <wolfssl/wolfcrypt/hash.h>

data Blake2b_160 = Blake2b_160 deriving (Show)
data Blake2b_224 = Blake2b_224 deriving (Show)
data Blake2b_256 = Blake2b_256 deriving (Show)
data Blake2b_384 = Blake2b_384 deriving (Show)
data Blake2b_512 = Blake2b_512 deriving (Show)


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
  type HashBlockSize           Blake2b_160 = 128
  type HashDigestSize          Blake2b_160 = 28
  type HashInternalContextSize Blake2b_160 = {#sizeof Blake2b#}

  hashBlockSize  _                    = 128
  hashDigestSize _                    = 28
  hashInternalContextSize _           = {#sizeof Blake2b#}

  hashInternalInit ctx                = void $
    withinAligned ({#sizeof Blake2b#}) 64 ctx $ \tmp -> do
      print ("wc_InitBlake2b", ctx, tmp)
      res <- wc_InitBlake2b tmp  28
      when (res /= 0) $ error "Failed to wc_InitBlake2b!"
      res <- wc_Blake2bUpdate tmp (castPtr ctx) 0 -- ensure we always run update at least once
      when (res /= 0) $ error "Failed to wc_Blake2bUpdate in init!"

  hashInternalUpdate ctx bytes n      = void $
    withinAligned ({#sizeof Blake2b#}) 64 ctx $ \tmp -> do -- wc_Blake2bUpdate tmp (castPtr bytes) (fromIntegral n)
      print ("Update with", n, "bytes", ctx, tmp)
      res <- wc_Blake2bUpdate tmp (castPtr ctx) 0 -- ensure we always run update at least once
      when (res /= 0) $ error "Failed to wc_Blake2bUpdate in init!"
  hashInternalFinalize ctx digest     = void $ do
    withinAligned ({#sizeof Blake2b#}) 64 ctx $ \tmp -> do
      print ("wc_Blake2bFinal", ctx, tmp)
      wc_Blake2bFinal tmp (castPtr digest) 28


foreign import capi unsafe "wolfssl/wolfcrypt/hash.h wc_InitBlake2b"
  wc_InitBlake2b :: Ptr (Context Blake2b_160) -> CUInt -> IO CInt

foreign import capi safe "wolfssl/wolfcrypt/hash.h wc_Blake2bUpdate"
  wc_Blake2bUpdate :: Ptr (Context Blake2b_160) -> Ptr CUChar -> CUInt -> IO CInt

foreign import capi unsafe "wolfssl/wolfcrypt/hash.h wc_Blake2bFinal"
  wc_Blake2bFinal :: Ptr (Context Blake2b_160) -> Ptr CUChar  -> CUInt -> IO CInt


withinAligned :: Int -> Int -> Ptr a -> (Ptr a -> IO b) -> IO b
withinAligned size alignment p f = do
  allocaBytesAligned size alignment $ \tmp -> do
    copyBytes tmp p size
    !b <- f tmp
    copyBytes p tmp size
    pure b


-- instance HashAlgorithm Blake2b_160 where
--   type HashBlockSize           Blake2b_160 = (#const BLAKE2B_BLOCKBYTES)
--   type HashDigestSize          Blake2b_160 = 20
--   type HashInternalContextSize Blake2b_160 = (#size Blake2b)
--   hashBlockSize  _          = (#const BLAKE2B_BLOCKBYTES)
--   hashDigestSize _          = 20
--   hashInternalContextSize _ = (#size Blake2b)
--   hashInternalInit = hInit $ \fctx -> let n = 160 `div` 8 in [CU.block|
--     int{
--       Blake2b stat = *((Blake2b *)$fptr-ptr:(hs_BLAKE2_160 *fctx));
--       // printf("wc_InitBlake2b(%p, %u)\n",$fptr-ptr:(hs_BLAKE2_160 *fctx), $(word32 n));
--       int ret = wc_InitBlake2b( &stat, $(word32 n));
--       *((Blake2b *)$fptr-ptr:(hs_BLAKE2_160 *fctx)) = stat;
--       return ret;
--       }
--     |]

--   hashInternalUpdate = hUpdate $ \fctx fptr n32 ->  [CU.block|
--     int{ // printf("wc_Blake2bUpdate(%p, %p, %u)\n",$fptr-ptr:(hs_BLAKE2_160 *fctx), $fptr-ptr:(byte *fptr), $(word32 n32));
--       Blake2b stat = *((Blake2b *)$fptr-ptr:(hs_BLAKE2_160 *fctx));
--       int ret=  wc_Blake2bUpdate( &stat , $fptr-ptr:(byte *fptr) , $(word32 n32) );
--       *((Blake2b *)$fptr-ptr:(hs_BLAKE2_160 *fctx)) = stat;
--       return ret;
--       }
--       |]
--       -- return wc_Blake2bUpdate( $fptr-ptr:(hs_BLAKE2_160 *fctx) , $fptr-ptr:(byte *fptr) , $(word32 n32) );

--   hashInternalFinalize = hFinalise $ \fctx fdig -> let n = 160 `div` 8 in [CU.block|
--     int{
--       Blake2b stat = *((Blake2b *)$fptr-ptr:(hs_BLAKE2_160 *fctx));
--       // printf("wc_Blake2bFinal(%p(%p), %u)\n",$fptr-ptr:(hs_BLAKE2_160 *fctx), &stat, $(word32 n));
--       int ret = wc_Blake2bFinal( &stat , $fptr-ptr:(byte *fdig) , $(word32 n));
--       *((Blake2b *)$fptr-ptr:(hs_BLAKE2_160 *fctx)) = stat;
--       return ret;
--       }
--     |]



-- instance HashAlgorithm Blake2b_224 where
--   type HashBlockSize           Blake2b_224 = (#const BLAKE2B_BLOCKBYTES)
--   type HashDigestSize          Blake2b_224 = 28
--   type HashInternalContextSize Blake2b_224 = (#size Blake2b)
--   hashBlockSize  _          = (#const BLAKE2B_BLOCKBYTES)
--   hashDigestSize _          = 28
--   hashInternalContextSize _ = (#size Blake2b)
--   hashInternalInit = hInit $ \fctx -> let n = 224 `div` 8 in [CU.block|
--     int{
--       Blake2b stat = *((Blake2b *)$fptr-ptr:(hs_BLAKE2_224 *fctx));
--       // printf("wc_InitBlake2b(%p, %u)\n",$fptr-ptr:(hs_BLAKE2_224 *fctx), $(word32 n));
--       int ret = wc_InitBlake2b( &stat, $(word32 n));
--       *((Blake2b *)$fptr-ptr:(hs_BLAKE2_224 *fctx)) = stat;
--       return ret;
--       }
--     |]

--   hashInternalUpdate = hUpdate $ \fctx fptr n32 ->  [CU.block|
--     int{ // printf("wc_Blake2bUpdate(%p, %p, %u)\n",$fptr-ptr:(hs_BLAKE2_224 *fctx), $fptr-ptr:(byte *fptr), $(word32 n32));
--       Blake2b stat = *((Blake2b *)$fptr-ptr:(hs_BLAKE2_224 *fctx));
--       int ret=  wc_Blake2bUpdate( &stat , $fptr-ptr:(byte *fptr) , $(word32 n32) );
--       *((Blake2b *)$fptr-ptr:(hs_BLAKE2_224 *fctx)) = stat;
--       return ret;
--       }
--       |]
--       -- return wc_Blake2bUpdate( $fptr-ptr:(hs_BLAKE2_224 *fctx) , $fptr-ptr:(byte *fptr) , $(word32 n32) );

--   hashInternalFinalize = hFinalise $ \fctx fdig -> let n = 224 `div` 8 in [CU.block|
--     int{
--       Blake2b stat = *((Blake2b *)$fptr-ptr:(hs_BLAKE2_224 *fctx));
--       // printf("wc_Blake2bFinal(%p(%p), %u)\n",$fptr-ptr:(hs_BLAKE2_224 *fctx), &stat, $(word32 n));
--       int ret = wc_Blake2bFinal( &stat , $fptr-ptr:(byte *fdig) , $(word32 n));
--       *((Blake2b *)$fptr-ptr:(hs_BLAKE2_224 *fctx)) = stat;
--       return ret;
--       }
--     |]

-- instance HashAlgorithm Blake2b_256 where
--   type HashBlockSize           Blake2b_256 = (#const BLAKE2B_BLOCKBYTES)
--   type HashDigestSize          Blake2b_256 = 32
--   type HashInternalContextSize Blake2b_256 = (#size Blake2b)
--   hashBlockSize  _          = (#const BLAKE2B_BLOCKBYTES)
--   hashDigestSize _          = 32
--   hashInternalContextSize _ = (#size Blake2b)
--   hashInternalInit = hInit $ \fctx -> let n = 256 `div` 8 in [CU.block|
--     int{
--       Blake2b stat = *((Blake2b *)$fptr-ptr:(hs_BLAKE2_256 *fctx));
--       // printf("wc_InitBlake2b(%p, %u)\n",$fptr-ptr:(hs_BLAKE2_256 *fctx), $(word32 n));
--       int ret = wc_InitBlake2b( &stat, $(word32 n));
--       *((Blake2b *)$fptr-ptr:(hs_BLAKE2_256 *fctx)) = stat;
--       return ret;
--       }
--     |]

--   hashInternalUpdate = hUpdate $ \fctx fptr n32 ->  [CU.block|
--     int{ // printf("wc_Blake2bUpdate(%p, %p, %u)\n",$fptr-ptr:(hs_BLAKE2_256 *fctx), $fptr-ptr:(byte *fptr), $(word32 n32));
--       Blake2b stat = *((Blake2b *)$fptr-ptr:(hs_BLAKE2_256 *fctx));
--       int ret=  wc_Blake2bUpdate( &stat , $fptr-ptr:(byte *fptr) , $(word32 n32) );
--       *((Blake2b *)$fptr-ptr:(hs_BLAKE2_256 *fctx)) = stat;
--       return ret;
--       }
--       |]
--       -- return wc_Blake2bUpdate( $fptr-ptr:(hs_BLAKE2_256 *fctx) , $fptr-ptr:(byte *fptr) , $(word32 n32) );

--   hashInternalFinalize = hFinalise $ \fctx fdig -> let n = 256 `div` 8 in [CU.block|
--     int{
--       Blake2b stat = *((Blake2b *)$fptr-ptr:(hs_BLAKE2_256 *fctx));
--       // printf("wc_Blake2bFinal(%p(%p), %u)\n",$fptr-ptr:(hs_BLAKE2_256 *fctx), &stat, $(word32 n));
--       int ret = wc_Blake2bFinal( &stat , $fptr-ptr:(byte *fdig) , $(word32 n));
--       *((Blake2b *)$fptr-ptr:(hs_BLAKE2_256 *fctx)) = stat;
--       return ret;
--       }
--     |]

-- instance HashAlgorithm Blake2b_384 where
--   type HashBlockSize           Blake2b_384 = (#const BLAKE2B_BLOCKBYTES)
--   type HashDigestSize          Blake2b_384 = 48
--   type HashInternalContextSize Blake2b_384 = (#size Blake2b)
--   hashBlockSize  _          = (#const BLAKE2B_BLOCKBYTES)
--   hashDigestSize _          = 48
--   hashInternalContextSize _ = (#size Blake2b)
--   hashInternalInit = hInit $ \fctx -> let n = 384 `div` 8 in [CU.block|
--     int{
--       Blake2b stat = *((Blake2b *)$fptr-ptr:(hs_BLAKE2_384 *fctx));
--       // printf("wc_InitBlake2b(%p, %u)\n",$fptr-ptr:(hs_BLAKE2_384 *fctx), $(word32 n));
--       int ret = wc_InitBlake2b( &stat, $(word32 n));
--       *((Blake2b *)$fptr-ptr:(hs_BLAKE2_384 *fctx)) = stat;
--       return ret;
--       }
--     |]

--   hashInternalUpdate = hUpdate $ \fctx fptr n32 ->  [CU.block|
--     int{ // printf("wc_Blake2bUpdate(%p, %p, %u)\n",$fptr-ptr:(hs_BLAKE2_384 *fctx), $fptr-ptr:(byte *fptr), $(word32 n32));
--       Blake2b stat = *((Blake2b *)$fptr-ptr:(hs_BLAKE2_384 *fctx));
--       int ret=  wc_Blake2bUpdate( &stat , $fptr-ptr:(byte *fptr) , $(word32 n32) );
--       *((Blake2b *)$fptr-ptr:(hs_BLAKE2_384 *fctx)) = stat;
--       return ret;
--       }
--       |]
--       -- return wc_Blake2bUpdate( $fptr-ptr:(hs_BLAKE2_384 *fctx) , $fptr-ptr:(byte *fptr) , $(word32 n32) );

--   hashInternalFinalize = hFinalise $ \fctx fdig -> let n = 384 `div` 8 in [CU.block|
--     int{
--       Blake2b stat = *((Blake2b *)$fptr-ptr:(hs_BLAKE2_384 *fctx));
--       // printf("wc_Blake2bFinal(%p(%p), %u)\n",$fptr-ptr:(hs_BLAKE2_384 *fctx), &stat, $(word32 n));
--       int ret = wc_Blake2bFinal( &stat , $fptr-ptr:(byte *fdig) , $(word32 n));
--       *((Blake2b *)$fptr-ptr:(hs_BLAKE2_384 *fctx)) = stat;
--       return ret;
--       }
--     |]


-- instance HashAlgorithm Blake2b_512 where
--   type HashBlockSize           Blake2b_512 = (#const BLAKE2B_BLOCKBYTES)
--   type HashDigestSize          Blake2b_512 = 64
--   type HashInternalContextSize Blake2b_512 = (#size Blake2b)
--   hashBlockSize  _          = (#const BLAKE2B_BLOCKBYTES)
--   hashDigestSize _          = 64
--   hashInternalContextSize _ = (#size Blake2b)
--   hashInternalInit = hInit $ \fctx -> let n = 512 `div` 8 in [CU.block|
--     int{
--       Blake2b stat = *((Blake2b *)$fptr-ptr:(hs_BLAKE2_512 *fctx));
--       // printf("wc_InitBlake2b(%p, %u)\n",$fptr-ptr:(hs_BLAKE2_512 *fctx), $(word32 n));
--       int ret = wc_InitBlake2b( &stat, $(word32 n));
--       *((Blake2b *)$fptr-ptr:(hs_BLAKE2_512 *fctx)) = stat;
--       return ret;
--       }
--     |]

--   hashInternalUpdate = hUpdate $ \fctx fptr n32 ->  [CU.block|
--     int{ // printf("wc_Blake2bUpdate(%p, %p, %u)\n",$fptr-ptr:(hs_BLAKE2_512 *fctx), $fptr-ptr:(byte *fptr), $(word32 n32));
--       Blake2b stat = *((Blake2b *)$fptr-ptr:(hs_BLAKE2_512 *fctx));
--       int ret=  wc_Blake2bUpdate( &stat , $fptr-ptr:(byte *fptr) , $(word32 n32) );
--       *((Blake2b *)$fptr-ptr:(hs_BLAKE2_512 *fctx)) = stat;
--       return ret;
--       }
--       |]
--       -- return wc_Blake2bUpdate( $fptr-ptr:(hs_BLAKE2_512 *fctx) , $fptr-ptr:(byte *fptr) , $(word32 n32) );

--   hashInternalFinalize = hFinalise $ \fctx fdig -> let n = 512 `div` 8 in [CU.block|
--     int{
--       Blake2b stat = *((Blake2b *)$fptr-ptr:(hs_BLAKE2_512 *fctx));
--       // printf("wc_Blake2bFinal(%p(%p), %u)\n",$fptr-ptr:(hs_BLAKE2_512 *fctx), &stat, $(word32 n));
--       int ret = wc_Blake2bFinal( &stat , $fptr-ptr:(byte *fdig) , $(word32 n));
--       *((Blake2b *)$fptr-ptr:(hs_BLAKE2_512 *fctx)) = stat;
--       return ret;
--       }
--     |]

