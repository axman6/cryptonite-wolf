{-# LANGUAGE DataKinds       #-}
{-# LANGUAGE EmptyDataDecls  #-}
{-# LANGUAGE QuasiQuotes     #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeFamilies    #-}


module Crypto.Wolf.Hash.MD where

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
#define WOLFSSL_MD2
#define WOLFSSL_MD5


C.include "<wolfssl/wolfcrypt/hash.h>" 
#include <wolfssl/wolfcrypt/hash.h>

instance HashAlgorithm MD5 where
  type HashBlockSize           MD5 = (#const MD5_BLOCK_SIZE)
  type HashDigestSize          MD5 = (#const MD5_DIGEST_SIZE)
  type HashInternalContextSize MD5 = (#size Md5)
  hashBlockSize  _          = (#const MD5_BLOCK_SIZE)
  hashDigestSize _          = (#const MD5_DIGEST_SIZE)
  hashInternalContextSize _ = (#size Md5)
  hashInternalInit = hInit $ \fctx -> [CU.exp|
    void{ wc_InitMd5( $fptr-ptr:(wc_Md5 *fctx))}
    |]

  hashInternalUpdate = hUpdate $ \fctx fptr n32 -> [CU.exp| 
    void{ wc_Md5Update( $fptr-ptr:(wc_Md5 *fctx) , $fptr-ptr:(byte *fptr) , $(word32 n32) ) }
    |]

  hashInternalFinalize = hFinalise $ \fctx fdig -> [CU.exp|
    void{ wc_Md5Final( $fptr-ptr:(wc_Md5 *fctx) , $fptr-ptr:(byte *fdig) ) } 
    |]