import std/[unittest, sequtils, strutils]
import ./twofish
import ./galois

# Recreate the qbox and generator to validate sbox values
const qbox: array[2, array[4, array[16, byte]]] = [
  [
    [0x8'u8, 0x1'u8, 0x7'u8, 0xD'u8, 0x6'u8, 0xF'u8, 0x3'u8, 0x2'u8, 0x0'u8, 0xB'u8, 0x5'u8, 0x9'u8, 0xE'u8, 0xC'u8, 0xA'u8, 0x4'u8],
    [0xE'u8, 0xC'u8, 0xB'u8, 0x8'u8, 0x1'u8, 0x2'u8, 0x3'u8, 0x5'u8, 0xF'u8, 0x4'u8, 0xA'u8, 0x6'u8, 0x7'u8, 0x0'u8, 0x9'u8, 0xD'u8],
    [0xB'u8, 0xA'u8, 0x5'u8, 0xE'u8, 0x6'u8, 0xD'u8, 0x9'u8, 0x0'u8, 0xC'u8, 0x8'u8, 0xF'u8, 0x3'u8, 0x2'u8, 0x4'u8, 0x7'u8, 0x1'u8],
    [0xD'u8, 0x7'u8, 0xF'u8, 0x4'u8, 0x1'u8, 0x2'u8, 0x6'u8, 0xE'u8, 0x9'u8, 0xB'u8, 0x3'u8, 0x0'u8, 0x8'u8, 0x5'u8, 0xC'u8, 0xA'u8],
  ],
  [
    [0x2'u8, 0x8'u8, 0xB'u8, 0xD'u8, 0xF'u8, 0x7'u8, 0x6'u8, 0xE'u8, 0x3'u8, 0x1'u8, 0x9'u8, 0x4'u8, 0x0'u8, 0xA'u8, 0xC'u8, 0x5'u8],
    [0x1'u8, 0xE'u8, 0x2'u8, 0xB'u8, 0x4'u8, 0xC'u8, 0x3'u8, 0x7'u8, 0x6'u8, 0xD'u8, 0xA'u8, 0x5'u8, 0xF'u8, 0x9'u8, 0x0'u8, 0x8'u8],
    [0x4'u8, 0xC'u8, 0x7'u8, 0x5'u8, 0x1'u8, 0x6'u8, 0x9'u8, 0xA'u8, 0x0'u8, 0xE'u8, 0xD'u8, 0x8'u8, 0x2'u8, 0xB'u8, 0x3'u8, 0xF'u8],
    [0xB'u8, 0x9'u8, 0x5'u8, 0x1'u8, 0xC'u8, 0x3'u8, 0xD'u8, 0xE'u8, 0x6'u8, 0x4'u8, 0x7'u8, 0xF'u8, 0x2'u8, 0x0'u8, 0x8'u8, 0xA'u8],
  ],
]

proc genSbox(qi: int, x: byte): byte =
  var a0 = int(x) div 16
  var b0 = int(x) mod 16
  for i in 0 .. 1:
    let a1 = a0 xor b0
    let b1 = (a0 xor (((b0 shl 3) or (b0 shr 1)) and 15) xor ((a0 shl 3) and 15)) and 15
    a0 = int(qbox[qi][2*i][a1])
    b0 = int(qbox[qi][2*i + 1][b1])
  return byte((b0 shl 4) + a0)

suite "Twofish":
  test "S-box values match qbox generator":
    for n in 0 .. 1:
      for m in 0 .. 255:
        check twofishSbox[n][m] == genSbox(n, byte(m))

  test "Block cipher test vectors":
    type TV = tuple[key: seq[byte], dec: array[16, byte], enc: array[16, byte]]
    let vectors: seq[TV] = @[
      (# LibTom test
        (@[0x9F'u8, 0x58, 0x9F, 0x5C, 0xF6, 0x12, 0x2C, 0x32, 0xB6, 0xBF, 0xEC, 0x2F, 0x2A, 0xE8, 0xC3, 0x5A]),
        [0xD4'u8, 0x91, 0xDB, 0x16, 0xE7, 0xB1, 0xC3, 0x9E, 0x86, 0xCB, 0x08, 0x6B, 0x78, 0x9F, 0x54, 0x19],
        [0x01'u8, 0x9F, 0x98, 0x09, 0xDE, 0x17, 0x11, 0x85, 0x8F, 0xAA, 0xC3, 0xA3, 0xBA, 0x20, 0xFB, 0xC3]
      ),
      (
        (@[0x88'u8, 0xB2, 0xB2, 0x70, 0x6B, 0x10, 0x5E, 0x36, 0xB4, 0x46, 0xBB, 0x6D, 0x73, 0x1A, 0x1E, 0x88,
             0xEF, 0xA7, 0x1F, 0x78, 0x89, 0x65, 0xBD, 0x44]),
        [0x39'u8, 0xDA, 0x69, 0xD6, 0xBA, 0x49, 0x97, 0xD5, 0x85, 0xB6, 0xDC, 0x07, 0x3C, 0xA3, 0x41, 0xB2],
        [0x18'u8, 0x2B, 0x02, 0xD8, 0x14, 0x97, 0xEA, 0x45, 0xF9, 0xDA, 0xAC, 0xDC, 0x29, 0x19, 0x3A, 0x65]
      ),
      (
        (@[0xD4'u8, 0x3B, 0xB7, 0x55, 0x6E, 0xA3, 0x2E, 0x46, 0xF2, 0xA2, 0x82, 0xB7, 0xD4, 0x5B, 0x4E, 0x0D,
             0x57, 0xFF, 0x73, 0x9D, 0x4D, 0xC9, 0x2C, 0x1B, 0xD7, 0xFC, 0x01, 0x70, 0x0C, 0xC8, 0x21, 0x6F]),
        [0x90'u8, 0xAF, 0xE9, 0x1B, 0xB2, 0x88, 0x54, 0x4F, 0x2C, 0x32, 0xDC, 0x23, 0x9B, 0x26, 0x35, 0xE6],
        [0x6C'u8, 0xB4, 0x56, 0x1C, 0x40, 0xBF, 0x0A, 0x97, 0x05, 0x93, 0x1C, 0xB6, 0xD4, 0x08, 0xE7, 0xFA]
      ),
      (# Schneier ECB
        (@[0x00'u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
        [0x00'u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0x9F'u8, 0x58, 0x9F, 0x5C, 0xF6, 0x12, 0x2C, 0x32, 0xB6, 0xBF, 0xEC, 0x2F, 0x2A, 0xE8, 0xC3, 0x5A]
      ),
      (
        (@[0x01'u8, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
             0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]),
        [0x00'u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0xCF'u8, 0xD1, 0xD2, 0xE5, 0xA9, 0xBE, 0x9C, 0xDF, 0x50, 0x1F, 0x13, 0xB8, 0x92, 0xBD, 0x22, 0x48]
      ),
      (
        (@[0x01'u8, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
             0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]),
        [0x00'u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0x37'u8, 0x52, 0x7B, 0xE0, 0x05, 0x23, 0x34, 0xB8, 0x9F, 0x0C, 0xFC, 0xCA, 0xE8, 0x7C, 0xFA, 0x20]
      )
    ]

    for tv in vectors:
      var ctx = newTwofishEcbCtx(tv.key)
      var output: array[16, byte]
      ctx.encrypt(tv.dec, output)
      check output == tv.enc
      ctx.decrypt(tv.enc, output)
      check output == tv.dec

      # 1000x encrypt then 1000x decrypt on zero block
      var zero: array[16, byte]
      var buf: array[16, byte]
      for i in 0 ..< 1000:
        ctx.encrypt(buf, buf)
      for i in 0 ..< 1000:
        ctx.decrypt(buf, buf)
      check buf == zero

  test "GHASH KATs (trivial cases)":
    # H = 0 => GHASH returns 0 for any AAD/data
    var H: Block128
    let aad = newSeq[byte](13) # arbitrary length
    let data = newSeq[byte](33)
    let y1 = ghash(H, aad, data)
    check:
      allIt(y1, it == 0'u8)
    # AAD = DATA = empty => GHASH returns 0 for any H
    for hval in [0'u8, 1'u8, 0xFF'u8]:
      for i in 0 ..< H.len: H[i] = hval
      let y2 = ghash(H, @[], @[])
      check allIt(y2, it == 0'u8)

  test "POLYVAL KATs (trivial cases)":
    # H = 0 => POLYVAL returns 0 for any AAD/data
    var H: Block128
    let aad = newSeq[byte](7)
    let data = newSeq[byte](25)
    let y1 = polyval(H, aad, data)
    check allIt(y1, it == 0'u8)
    # AAD = DATA = empty => POLYVAL returns 0 for any H
    for hval in [0'u8, 0xA5'u8, 0xFF'u8]:
      for i in 0 ..< H.len: H[i] = hval
      let y2 = polyval(H, @[], @[])
      check allIt(y2, it == 0'u8)

  test "CBC round-trip and chunking (16-byte aligned)":
    let key = toSeq("0123456789ABCDEFGHIJKLMNOPQRSTUV".mapIt(byte(it)))
    let iv = toSeq("0000000000000000".mapIt(byte(it)))
    var ctxAll = newTwofishCbcCtx(key, iv)
    var ctxChunks = newTwofishCbcCtx(key, iv)
    # input: 64 bytes (aligned)
    var input = newSeq[byte](64)
    for i in 0 ..< input.len: input[i] = byte(i)
    let ctAll = ctxAll.encrypt(input)
    # chunked in 16|32|16
    var bufCt = newSeq[byte](64)
    var off = 0
    for sz in [16, 32, 16]:
      var part = ctxChunks.encrypt(input[off ..< off + sz])
      for i in 0 ..< sz: bufCt[off + i] = part[i]
      off += sz
    check ctAll == bufCt
    # decrypt chunked and all
    let ptAll = ctxAll.decrypt(ctAll)
    check ptAll == input
    var outPt = newSeq[byte](64)
    off = 0
    for sz in [16, 32, 16]:
      var part = ctxChunks.decrypt(bufCt[off ..< off + sz])
      for i in 0 ..< sz: outPt[off + i] = part[i]
      off += sz
    check outPt == input

  test "CTR round-trip and chunking":
    let keyStr = "0123456789ABCDEFGHIJKLMNOPQRSTUV"
    let nonceStr = "12345678"
    var ctxAll = newTwofishCtrCtx(keyStr, nonceStr, 0)
    var ctxChunks = newTwofishCtrCtx(keyStr, nonceStr, 0)
    var input = newSeq[byte](77)
    for i in 0 ..< input.len: input[i] = byte(255 - i)
    # one-shot
    let ctAll = ctxAll.encrypt(input)
    # chunked with block-aligned boundaries except final partial
    var buf = newSeq[byte](input.len)
    var off = 0
    for sz in [16, 16, 16, 16, input.len - 64]:
      let take = min(sz, input.len - off)
      var part = ctxChunks.encrypt(input[off ..< off + take])
      for i in 0 ..< take: buf[off + i] = part[i]
      off += take
      if off >= input.len: break
    check ctAll == buf
    # decrypt one-shot
    let ptAll = ctxAll.decrypt(ctAll)
    check ptAll == input
    # decrypt chunked
    var outPt = newSeq[byte](input.len)
    off = 0
    var dctx = newTwofishCtrCtx(keyStr, nonceStr, 0)
    for sz in [16, 16, 16, 16, ctAll.len - 64]:
      let take = min(sz, ctAll.len - off)
      var part = dctx.decrypt(ctAll[off ..< off + take])
      for i in 0 ..< take: outPt[off + i] = part[i]
      off += take
      if off >= ctAll.len: break
    check outPt == input

  test "XTS round-trip (full and partial block)":
    let key1 = toSeq("0123456789ABCDEFGHIJKLMNOPQRSTUV".mapIt(byte(it)))
    let key2 = toSeq("VUTSRQPONMLKJIHGFEDCBA9876543210".mapIt(byte(it)))
    var x = newTwofishXtsCtx(key1, key2)
    var tweak = toSeq("0000000000000000".mapIt(byte(it)))
    # multiple of blocksize
    var pt1 = newSeq[byte](64)
    for i in 0 ..< pt1.len: pt1[i] = byte(i * 3)
    let ct1 = x.encrypt(tweak, pt1)
    let rt1 = x.decrypt(tweak, ct1)
    check rt1 == pt1
    # with partial final block
    var pt2 = newSeq[byte](37)
    for i in 0 ..< pt2.len: pt2[i] = byte(i * 5)
    let ct2 = x.encrypt(tweak, pt2)
    let rt2 = x.decrypt(tweak, ct2)
    check rt2 == pt2

  test "GCM round-trip and tamper detect":
    let key = toSeq("0123456789ABCDEFGHIJKLMNOPQRSTUV".mapIt(byte(it)))
    let iv = toSeq("iv-96-bits".mapIt(byte(it))) & @[0'u8, 0'u8, 0'u8] # make 12 bytes
    var g = newTwofishGcmCtx(key, iv)
    let aad = toSeq("header".mapIt(byte(it)))
    let pt = toSeq("hello gcm with twofish".mapIt(byte(it)))
    var ct = newSeq[byte](pt.len)
    var tag = newSeq[byte](16)
    g.encrypt(aad, pt, ct, tag)
    var dec = newSeq[byte](pt.len)
    g.decrypt(aad, ct, dec, tag)
    check dec == pt
    # tamper tag
    var badTag = tag
    badTag[0] = badTag[0] xor 1
    expect(ValueError):
      discard g.decrypt(aad, ct, badTag)
    # tamper ciphertext
    var badCt = ct
    badCt[0] = badCt[0] xor 1
    expect(ValueError):
      discard g.decrypt(aad, badCt, tag)

  test "GCM-SIV round-trip and tamper detect":
    let kgen = toSeq("SixteenByteKey__".mapIt(byte(it)))
    let nonce = toSeq("0123456789ab".mapIt(byte(it)))
    var s = newTwofishGcmSivCtx(kgen, nonce)
    let aad = toSeq("associated".mapIt(byte(it)))
    let pt = toSeq("hello gcm-siv with twofish".mapIt(byte(it)))
    var ct = newSeq[byte](pt.len)
    var tag = newSeq[byte](16)
    s.encrypt(aad, pt, ct, tag)
    let dec = s.decrypt(aad, ct, tag)
    check dec == pt
    # tamper
    var badTag = tag
    badTag[15] = badTag[15] xor 0x80'u8
    expect(ValueError):
      discard s.decrypt(aad, ct, badTag)
