import std/[sequtils, strutils]

#[
  key sizes (int bytes -> bits):
    16 -> 128bit
    24 -> 192bit
    32 -> 256bit
]#

const blocksize = 16

type
  TwoFishCtx = object of RootObj
    s:              array[4,  array[256, uint32]]
    k:              array[40, uint32]
  TwofishEcbCtx* = object of TwoFishCtx # Electronic CodeBook
  TwofishCbcCtx* = object of TwoFishCtx # Ciphertext Block Chaining
    iv: seq[byte]
    previousBlock:  array[blocksize, byte]
    isEncryptState: bool
  TwofishCtrCtx* = object of TwoFishCtx # Counter
    nonce:          seq[byte]
    initValue:      array[8, byte]
    counter:        array[blocksize, byte]
    isEncryptState: bool

include twofish

#################################################################################

proc encodeBytes(s: string): seq[byte] =
  ## encode ascii string to bytes
  result = newSeq[byte](s.len)
  for i, c in s:
    result[i] = byte(c)
  
  return result


proc decodeBytes(bs: openArray[byte]): string =
  ## decode bytes to ascii string
  result = newStringOfCap(bs.len)
  for i, b in bs:
    result.add(char(b))
  
  return result


proc padPKCS7*(data: openArray[byte]): seq[byte] =
  let paddingLen = 16 - (len(data) mod 16)
  let paddingByte = paddingLen.byte
  result = newSeqOfCap[byte](len(data) + paddingLen)
  result.add(data)
  for _ in 1 .. paddingLen:
    result.add(paddingByte)


proc unpadPKCS7*(data: openArray[byte]): seq[byte] =
  if data.len == 0 or data.len mod 16 != 0:
    raise newException(ValueError, "Invalid padded data length")
  
  let paddingLen = data[^1].int
  if paddingLen < 1 or paddingLen > 16:
    raise newException(ValueError, "Invalid padding length")
  
  for i in 1 .. paddingLen:
    if data[data.len - i] != paddingLen.byte:
      raise newException(ValueError, "Invalid padding")
  result = data[0 ..< data.len - paddingLen]


proc xorBlocks(this: var openArray[byte], that: openArray[byte]) =
  for i in 0 ..< this.len:
    this[i] = this[i] xor that[i]


proc xorBlocks(this: openArray[byte], that: openArray[byte]): array[blocksize, byte] =
  for i in 0 ..< this.len:
    result[i] = this[i] xor that[i]


proc xorBlocksSeq(this: openArray[byte], that: openArray[byte]): seq[byte] =
  result = newSeq[byte](this.len)
  for i in 0 ..< this.len:
    result[i] = this[i] xor that[i]


proc initPreviousBlock(ctx: var TwofishCbcCtx) =
  ## initialize previous block with IV
  for i, b in ctx.iv:
    ctx.previousBlock[i] = b


proc initCounter*(ctx: var TwofishCtrCtx) =
  ## initialize counter with IV
  for i, b in ctx.nonce:
    ctx.counter[i] = b
  for i, b in ctx.initValue:
    ctx.counter[8 + i] = b


proc incrementCounter(ctx: var TwofishCtrCtx) =
  for i in countdown(15, 8):
    ctx.counter[i] = ctx.counter[i] + 1
    if ctx.counter[i] != 0:  # No overflow for this byte
      return
  raise newException(OverflowDefect, "counter overflow")


proc intToBytesBE(n: uint64): seq[byte] =
  ## big endian
  result = newSeq[byte](8)
  for i in 0 ..< 8:
    result[7 - i] = byte((n shr (i * 8)) and 0xFF)


proc intToBytesBE(n: int): seq[byte] =
  ## big endian
  result = newSeq[byte](4)
  for i in 0 ..< 4:
    result[3 - i] = byte((n shr (i * 4)) and 0xFF)


proc hexDigest*(data: openArray[byte]): string =
  ## produces a hex string of length data.len * 2
  result = newStringOfCap(data.len + data.len)
  for b in data:
    result.add(b.toHex(2).toLowerAscii())

  return result


proc `$`*(data: seq[byte]): string =
  return decodeBytes(data)

#################################################################################
# ECB
#################################################################################

proc encrypt*(ctx: TwofishEcbCtx, input: openArray[byte], output: var openArray[byte]) =
  ## ECB Mode
  ## encrypt in place
  if input.len mod blocksize != 0:
    raise newException(ValueError, "input length must be a multiple of 16")
  if input.len > output.len:
    raise newException(ValueError, "output length must be >= input length")

  var blk: array[blocksize, byte]

  for i in countup(0, input.len - 1, step=blocksize):
    ctx.twofishEncrypt(input[i ..< i + blocksize], blk)
    for j, b in blk:
      output[i + j] = b


proc encrypt*(ctx: TwofishEcbCtx, input: openArray[byte]): seq[byte] =
  ## ECB Mode
  ## returns ciphertext as new sequence
  if input.len mod blocksize != 0:
    raise newException(ValueError, "input length must be a multiple of 16")

  var blk: array[blocksize, byte]
  result = newSeq[byte](input.len)

  for i in countup(0, input.len - 1, step=blocksize):
    ctx.twofishEncrypt(input[i ..< i + blocksize], blk)
    for j, b in blk:
      result[i + j] = b

  return result


proc encrypt*(ctx: TwofishEcbCtx, input: string, output: var openArray[byte]) =
  ## ECB Mode
  ## encrypt in place
  encrypt(ctx, input.encodeBytes(), output)


proc encrypt*(ctx: TwofishEcbCtx, input: string): seq[byte] =
  ## ECB Mode
  ## returns ciphertext as new sequence
  return encrypt(ctx, input.encodeBytes())


proc decrypt*(ctx: TwofishEcbCtx, input: openArray[byte], output: var openArray[byte]) =
  ## EBC Mode
  ## decrypt in place
  if input.len mod blocksize != 0:
    raise newException(ValueError, "input length must be a multiple of 16")
  if input.len > output.len:
    raise newException(ValueError, "output length must be >= input length")

  var blk: array[blocksize, byte]

  for i in countup(0, input.len.pred, step=blocksize):
    ctx.twofishDecrypt(input, blk)
    for j, b in blk:
      output[i + j] = b


proc decrypt*(ctx: TwofishEcbCtx, input: openArray[byte]): seq[byte] =
  ## EBC Mode
  ## returns ciphertext as new sequence
  if input.len mod blocksize != 0:
    raise newException(ValueError, "input length must be a multiple of 16")

  var blk: array[blocksize, byte]
  result = newSeq[byte](input.len)

  for i in countup(0, input.len.pred, step=blocksize):
    ctx.twofishDecrypt(input[i ..< i + blocksize], blk)
    for j, b in blk:
      result[i + j] = b

  return result


proc decrypt*(ctx: TwofishEcbCtx, input: string, output: var openArray[byte]) =
  ## EBC Mode
  ## decrypt in place
  decrypt(ctx, input.encodeBytes(), output)


proc decrypt*(ctx: TwofishEcbCtx, input: string): seq[byte] =
  ## EBC Mode
  ## returns ciphertext as new sequence
  return decrypt(ctx, input.encodeBytes())

#################################################################################
# CBC
#################################################################################

proc encrypt*(ctx: var TwofishCbcCtx, input: openArray[byte], output: var openArray[byte]) =
  ## CBC Mode
  ## encrypt in place
  if input.len mod blocksize != 0:
    raise newException(ValueError, "input length must be a multiple of 16")
  if input.len > output.len:
    raise newException(ValueError, "output length must be >= input length")

  var blk: array[blocksize, byte]

  if not ctx.isEncryptState:
    ctx.initPreviousBlock()
    ctx.isEncryptState = true


  for i in countup(0, input.high, step=blocksize):
    # XOR with previous ciphertext block (or IV)
    ctx.twofishEncrypt(xorBlocks(input[i ..< i + blocksize], ctx.previousBlock), blk)
    for j, b in blk:
      output[i + j] = b
    ctx.previousBlock = blk


proc encrypt*(ctx: var TwofishCbcCtx, input: openArray[byte]): seq[byte] =
  ## CBC Mode
  ## returns ciphertext as new sequence
  if input.len mod blocksize != 0:
    raise newException(ValueError, "input length must be a multiple of 16")

  var blk: array[blocksize, byte]
  result = newSeq[byte](input.len)

  if not ctx.isEncryptState:
    ctx.initPreviousBlock()
    ctx.isEncryptState = true

  for i in countup(0, input.high, step=blocksize):
    # XOR with previous ciphertext block (or IV)
    ctx.twofishEncrypt(xorBlocks(input[i ..< i + blocksize], ctx.previousBlock), blk)
    for j, b in blk:
      result[i + j] = b
    ctx.previousBlock = blk

  return result


proc encrypt*(ctx: var TwofishCbcCtx, input: string, output: var openArray[byte]) =
  ## CBC Mode
  ## encrypt in place
  encrypt(ctx, input.encodeBytes(), output)


proc encrypt*(ctx: var TwofishCbcCtx, input: string): seq[byte] =
  ## CBC Mode
  ## returns ciphertext as new sequence
  return encrypt(ctx, input.encodeBytes())


proc decrypt*(ctx: var TwofishCbcCtx, input: openArray[byte], output: var openArray[byte]) =
  ## CBC Mode
  ## decrypt in place
  if input.len mod blocksize != 0:
    raise newException(ValueError, "input length must be a multiple of 16")
  if input.len > output.len:
    raise newException(ValueError, "output length must be >= input length")

  var ptBlk: array[blocksize, byte]
  var ctBlk: array[blocksize, byte]

  if ctx.isEncryptState:
    ctx.initPreviousBlock()
    ctx.isEncryptState = false

  for i in countup(0, input.high, step=blocksize):
    for i, b in input[i ..< i + blocksize]:
      ptBlk[i] = b
    ctx.twofishDecrypt(ptBlk, ctBlk)
    # XOR with previous ciphertext block (or IV for the first block)
    xorBlocks(ctBlk, ctx.previousBlock)
    for j, b in ctBlk:
      output[i + j] = b
    
    ctx.previousBlock = ptBlk


proc decrypt*(ctx: var TwofishCbcCtx, input: openArray[byte]): seq[byte] =
  ## CBC Mode
  ## returns ciphertext as new sequence
  if input.len mod blocksize != 0:
    raise newException(ValueError, "input length must be a multiple of 16")

  var ptBlk: array[blocksize, byte]
  var ctBlk: array[blocksize, byte]
  result = newSeq[byte](input.len)

  if ctx.isEncryptState:
    ctx.initPreviousBlock()
    ctx.isEncryptState = false

  for i in countup(0, input.high, step=blocksize):
    for i, b in input[i ..< i + blocksize]:
      ptBlk[i] = b
    ctx.twofishDecrypt(ptBlk, ctBlk)
    # XOR with previous ciphertext block (or IV for the first block)
    xorBlocks(ctBlk, ctx.previousBlock)
    for j, b in ctBlk:
      result[i + j] = b
    ctx.previousBlock = ptBlk

  return result


proc decrypt*(ctx: var TwofishCbcCtx, input: string, output: var openArray[byte]) =
  ## CBC Mode
  ## decrypt in place
  decrypt(ctx, input.encodeBytes(), output)


proc decrypt*(ctx: var TwofishCbcCtx, input: string): seq[byte] =
  ## CBC Mode
  ## returns ciphertext as new sequence
  return decrypt(ctx, input.encodeBytes())

#################################################################################
# CTR
#################################################################################

proc crypt*(ctx: var TwofishCtrCtx, input: openArray[byte], output: var openArray[byte]) =
  ## CTR Mode
  ## crypt in place
  if input.len > output.len:
    raise newException(ValueError, "output length must be >= input length")

  var blk: array[blocksize, byte]

  for i in countup(0, input.high, step=blocksize):
    # Encrypt the counter
    ctx.twofishEncrypt(ctx.counter, blk)
    ctx.incrementCounter()
    # XOR the encrypted counter with the block
    for j, b in xorBlocksSeq(input[i ..< min(i + blocksize, input.len)], blk):
      output[i + j] = b


proc crypt*(ctx: var TwofishCtrCtx, input: openArray[byte]): seq[byte] =
  ## CTR Mode
  ## returns result as new sequence
  var blk: array[blocksize, byte]
  result = newSeq[byte](input.len)

  for i in countup(0, input.high, step=blocksize):
    # Encrypt the counter
    ctx.twofishEncrypt(ctx.counter, blk)
    ctx.incrementCounter()
    # XOR the encrypted counter with the block
    for j, b in xorBlocksSeq(input[i ..< min(i + blocksize, input.len)], blk):
      result[i + j] = b

  return result


proc encrypt*(ctx: var TwofishCtrCtx, input: openArray[byte], output: var openArray[byte]) =
  ## CTR Mode
  ## encrypt in place
  if not ctx.isEncryptState:
    ctx.initCounter()
    ctx.isEncryptState = true
  crypt(ctx, input, output)


proc encrypt*(ctx: var TwofishCtrCtx, input: openArray[byte]): seq[byte] =
  ## CTR Mode
  ## returns ciphertext as new sequence
  if not ctx.isEncryptState:
    ctx.initCounter()
    ctx.isEncryptState = true
  return crypt(ctx, input)


proc encrypt*(ctx: var TwofishCtrCtx, input: string, output: var openArray[byte]) =
  ## CTR Mode
  ## encrypt in place
  if not ctx.isEncryptState:
    ctx.initCounter()
    ctx.isEncryptState = true
  crypt(ctx, input.encodeBytes(), output)


proc encrypt*(ctx: var TwofishCtrCtx, input: string): seq[byte] =
  ## CTR Mode
  ## returns ciphertext as new sequence
  if not ctx.isEncryptState:
    ctx.initCounter()
    ctx.isEncryptState = true
  return crypt(ctx, input.encodeBytes())


proc decrypt*(ctx: var TwofishCtrCtx, input: openArray[byte], output: var openArray[byte]) =
  ## CTR Mode
  ## decrypt in place
  if ctx.isEncryptState:
    ctx.initCounter()
    ctx.isEncryptState = false
  crypt(ctx, input, output)


proc decrypt*(ctx: var TwofishCtrCtx, input: openArray[byte]): seq[byte] =
  ## CTR Mode
  ## returns ciphertext as new sequence
  if ctx.isEncryptState:
    ctx.initCounter()
    ctx.isEncryptState = false
  return crypt(ctx, input)


proc decrypt*(ctx: var TwofishCtrCtx, input: string, output: var openArray[byte]) =
  ## CTR Mode
  ## decrypt in place
  if ctx.isEncryptState:
    ctx.initCounter()
    ctx.isEncryptState = false
  crypt(ctx, input.encodeBytes(), output)


proc decrypt*(ctx: var TwofishCtrCtx, input: string): seq[byte] =
  ## CTR Mode
  ## returns ciphertext as new sequence
  if ctx.isEncryptState:
    ctx.initCounter()
    ctx.isEncryptState = false
  return crypt(ctx, input.encodeBytes())

#################################################################################

proc newTwofishEcbCtx*(key: openArray[byte]): TwofishEcbCtx =
  if not key.len in {16, 24, 32}:
    raise newException(ValueError, "Key must be 16/24/32 bytes long")
  
  init(key, result.s, result.k)


proc newTwofishEcbCtx*(key: string): TwofishEcbCtx =
  return newTwofishEcbCtx(key.encodeBytes())


proc newTwofishCbcCtx*(key, iv: openArray[byte]): TwofishCbcCtx =
  if not key.len in {16, 24, 32}:
    raise newException(ValueError, "Key must be 16/24/32 bytes long")
  if iv.len != 16:
    raise newException(ValueError, "Initialization vector (IV) must be 16 bytes long")
  result.iv = toSeq(iv)
  result.initPreviousBlock()
  
  init(key, result.s, result.k)


proc newTwofishCbcCtx*(key, iv: string): TwofishCbcCtx =
  return newTwofishCbcCtx(key.encodeBytes(), iv.encodeBytes())


proc newTwofishCtrCtx*(key, nonce: openArray[byte], initValue: openArray[byte]=newSeq[byte](8)): TwofishCtrCtx =
  # NOTE: we do not support variable length nonce/initValue
  if not key.len in {16, 24, 32}:
    raise newException(ValueError, "Key must be 16/24/32 bytes long")
  if nonce.len != 8:
    raise newException(ValueError, "Nonce must be 8 bytes long")
  if initValue.len != 8:
    raise newException(ValueError, "Initial state must be 8 bytes long")
  
  result.nonce = toSeq(nonce)
  for i, b in initValue:
    result.initValue[i] = b
  result.initCounter()

  init(key, result.s, result.k)


proc newTwofishCtrCtx*(key, nonce: string, initValue: int = 0): TwofishCtrCtx =
  return newTwofishCtrCtx(key.encodeBytes(), nonce.encodeBytes(), intToBytesBE(uint64(initValue)))

#################################################################################

when isMainModule:
  import base64
  
  let
    message = "This is a message of length 32!!" # 32
    key = "0123456789ABCDEFGHIJKLMNOPQRSTUV" # 32
    iv = "0000000000000000" # 16

  var ctx = newTwofishCbcCtx(key, iv)
  
  let ciphertext = ctx.encrypt(message)
  echo encode(ciphertext)
  doAssert encode(ciphertext) == "Y8wR7y7KDN7rGejB7b7GKLJbhIuOY9r7uwUvwFUeCJg=" # CBC
  
  let plaintext = ctx.decrypt(ciphertext)
  echo plaintext
  doAssert $plaintext == message
