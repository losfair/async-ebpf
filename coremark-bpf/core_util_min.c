#include "coremark.h"

ee_u16
crcu8(ee_u8 data, ee_u16 crc)
{
  ee_u8 i = 0, x16 = 0, carry = 0;

  for (i = 0; i < 8; i++) {
    x16 = (ee_u8)((data & 1) ^ ((ee_u8)crc & 1));
    data >>= 1;

    if (x16 == 1) {
      crc ^= 0x4002;
      carry = 1;
    } else {
      carry = 0;
    }
    crc >>= 1;
    if (carry) {
      crc |= 0x8000;
    } else {
      crc &= 0x7fff;
    }
  }
  return crc;
}

ee_u16
crcu16(ee_u16 newval, ee_u16 crc)
{
  crc = crcu8((ee_u8)(newval), crc);
  crc = crcu8((ee_u8)((newval) >> 8), crc);
  return crc;
}

ee_u16
crc16(ee_s16 newval, ee_u16 crc)
{
  return crcu16((ee_u16)newval, crc);
}

ee_u16
crcu32(ee_u32 newval, ee_u16 crc)
{
  crc = crc16((ee_s16)newval, crc);
  crc = crc16((ee_s16)(newval >> 16), crc);
  return crc;
}
