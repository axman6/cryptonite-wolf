module Crypto.Wolf.Hash.Types where

import           Data.ByteArray

data MD2 = MD2 deriving (Show)
data MD4 = MD4 deriving (Show)
data MD5 = MD5 deriving (Show)



data AES128 = AES128 ScrubbedBytes deriving (Show)
