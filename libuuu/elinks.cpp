#include "elinks.h"
#include "libusb.h"
#include "hidreport.h"
#include "liberror.h"
#include "libcomm.h"
#include "buffer.h"
#include "sdp.h"
#include "trans.h"

extern "C" {
#include "setupapi.h" 
#include "hidsdi.h"
}

#define DATABUF_LEN	64
#define FEATURE_DATA_LEN	128
#define FEATURE_PACKET_LEN	(FEATURE_DATA_LEN+2)

#define TAGINFO_DEFAULT_BEGIN   UINT8_C(1)
/* Implementation define: len is stored by 1 byte */
#define TAGINFO_START_LEN       (sizeof(uint8_t)*3)
enum
{
  TAGINFO_DEFAULT_START = UINT8_C(0),
  /* ... */
  TAGINFO_DEFAULT_END = UINT8_MAX,
};

enum
{
  DFU_INFO_SIGN = TAGINFO_DEFAULT_BEGIN,
  DFU_INFO_VERSION,
  DFU_INFO_UID_STR,
  DFU_INFO_PART_ID,
  DFU_INFO_PART_NAME,
  DFU_INFO_PART_SIZE,
};

/* Minor Command */
#define DFU_SWITCH2DFU		0x00
#define DFU_SWITCH2APP		0x01
#define DFU_START_UPGRADE	0x02
#define DFU_END_UPGRADE		0x03
#define DFU_SEND_DATA		0x04
#define DFU_VERIFY			0x05
#define DFU_CLEAR_ERR       0x06
#define DFU_SWITCH_PART     0x07
#define DFU_EXECUTE_ADDRESS 0X08

#define DFU_GET_INFO		0x85
#define DFU_GET_STATUS		0x86
#define DFU_GET_APP_VERSION 0x87
#define DFU_SET_MASTER_MODE 0x10

/* DFU State */
#define START			0x00
#define APP_IDLE		0x01
#define DFU_IDLE		0x02
#define DNLOAD			0x03
#define DNBUSY			0x04

/* DFU Status */
#define DFU_OK			0x00
#define DFU_ERROR		0x01
#define DFU_PENDING		0x02

/* Signature Bytes */
#define SIGNATURE		0x12345678

#if 0
enum
{
  DFU_INFO_SIGN = TAGINFO_DEFAULT_BEGIN,
  DFU_INFO_VERSION,
  DFU_INFO_UID_STR,
  DFU_INFO_PART_ID,
  DFU_INFO_PART_NAME,
  DFU_INFO_PART_SIZE,
};
#endif

static const unsigned int crc32_table[] =
{
  0x00000000, 0x04c11db7, 0x09823b6e, 0x0d4326d9,
  0x130476dc, 0x17c56b6b, 0x1a864db2, 0x1e475005,
  0x2608edb8, 0x22c9f00f, 0x2f8ad6d6, 0x2b4bcb61,
  0x350c9b64, 0x31cd86d3, 0x3c8ea00a, 0x384fbdbd,
  0x4c11db70, 0x48d0c6c7, 0x4593e01e, 0x4152fda9,
  0x5f15adac, 0x5bd4b01b, 0x569796c2, 0x52568b75,
  0x6a1936c8, 0x6ed82b7f, 0x639b0da6, 0x675a1011,
  0x791d4014, 0x7ddc5da3, 0x709f7b7a, 0x745e66cd,
  0x9823b6e0, 0x9ce2ab57, 0x91a18d8e, 0x95609039,
  0x8b27c03c, 0x8fe6dd8b, 0x82a5fb52, 0x8664e6e5,
  0xbe2b5b58, 0xbaea46ef, 0xb7a96036, 0xb3687d81,
  0xad2f2d84, 0xa9ee3033, 0xa4ad16ea, 0xa06c0b5d,
  0xd4326d90, 0xd0f37027, 0xddb056fe, 0xd9714b49,
  0xc7361b4c, 0xc3f706fb, 0xceb42022, 0xca753d95,
  0xf23a8028, 0xf6fb9d9f, 0xfbb8bb46, 0xff79a6f1,
  0xe13ef6f4, 0xe5ffeb43, 0xe8bccd9a, 0xec7dd02d,
  0x34867077, 0x30476dc0, 0x3d044b19, 0x39c556ae,
  0x278206ab, 0x23431b1c, 0x2e003dc5, 0x2ac12072,
  0x128e9dcf, 0x164f8078, 0x1b0ca6a1, 0x1fcdbb16,
  0x018aeb13, 0x054bf6a4, 0x0808d07d, 0x0cc9cdca,
  0x7897ab07, 0x7c56b6b0, 0x71159069, 0x75d48dde,
  0x6b93dddb, 0x6f52c06c, 0x6211e6b5, 0x66d0fb02,
  0x5e9f46bf, 0x5a5e5b08, 0x571d7dd1, 0x53dc6066,
  0x4d9b3063, 0x495a2dd4, 0x44190b0d, 0x40d816ba,
  0xaca5c697, 0xa864db20, 0xa527fdf9, 0xa1e6e04e,
  0xbfa1b04b, 0xbb60adfc, 0xb6238b25, 0xb2e29692,
  0x8aad2b2f, 0x8e6c3698, 0x832f1041, 0x87ee0df6,
  0x99a95df3, 0x9d684044, 0x902b669d, 0x94ea7b2a,
  0xe0b41de7, 0xe4750050, 0xe9362689, 0xedf73b3e,
  0xf3b06b3b, 0xf771768c, 0xfa325055, 0xfef34de2,
  0xc6bcf05f, 0xc27dede8, 0xcf3ecb31, 0xcbffd686,
  0xd5b88683, 0xd1799b34, 0xdc3abded, 0xd8fba05a,
  0x690ce0ee, 0x6dcdfd59, 0x608edb80, 0x644fc637,
  0x7a089632, 0x7ec98b85, 0x738aad5c, 0x774bb0eb,
  0x4f040d56, 0x4bc510e1, 0x46863638, 0x42472b8f,
  0x5c007b8a, 0x58c1663d, 0x558240e4, 0x51435d53,
  0x251d3b9e, 0x21dc2629, 0x2c9f00f0, 0x285e1d47,
  0x36194d42, 0x32d850f5, 0x3f9b762c, 0x3b5a6b9b,
  0x0315d626, 0x07d4cb91, 0x0a97ed48, 0x0e56f0ff,
  0x1011a0fa, 0x14d0bd4d, 0x19939b94, 0x1d528623,
  0xf12f560e, 0xf5ee4bb9, 0xf8ad6d60, 0xfc6c70d7,
  0xe22b20d2, 0xe6ea3d65, 0xeba91bbc, 0xef68060b,
  0xd727bbb6, 0xd3e6a601, 0xdea580d8, 0xda649d6f,
  0xc423cd6a, 0xc0e2d0dd, 0xcda1f604, 0xc960ebb3,
  0xbd3e8d7e, 0xb9ff90c9, 0xb4bcb610, 0xb07daba7,
  0xae3afba2, 0xaafbe615, 0xa7b8c0cc, 0xa379dd7b,
  0x9b3660c6, 0x9ff77d71, 0x92b45ba8, 0x9675461f,
  0x8832161a, 0x8cf30bad, 0x81b02d74, 0x857130c3,
  0x5d8a9099, 0x594b8d2e, 0x5408abf7, 0x50c9b640,
  0x4e8ee645, 0x4a4ffbf2, 0x470cdd2b, 0x43cdc09c,
  0x7b827d21, 0x7f436096, 0x7200464f, 0x76c15bf8,
  0x68860bfd, 0x6c47164a, 0x61043093, 0x65c52d24,
  0x119b4be9, 0x155a565e, 0x18197087, 0x1cd86d30,
  0x029f3d35, 0x065e2082, 0x0b1d065b, 0x0fdc1bec,
  0x3793a651, 0x3352bbe6, 0x3e119d3f, 0x3ad08088,
  0x2497d08d, 0x2056cd3a, 0x2d15ebe3, 0x29d4f654,
  0xc5a92679, 0xc1683bce, 0xcc2b1d17, 0xc8ea00a0,
  0xd6ad50a5, 0xd26c4d12, 0xdf2f6bcb, 0xdbee767c,
  0xe3a1cbc1, 0xe760d676, 0xea23f0af, 0xeee2ed18,
  0xf0a5bd1d, 0xf464a0aa, 0xf9278673, 0xfde69bc4,
  0x89b8fd09, 0x8d79e0be, 0x803ac667, 0x84fbdbd0,
  0x9abc8bd5, 0x9e7d9662, 0x933eb0bb, 0x97ffad0c,
  0xafb010b1, 0xab710d06, 0xa6322bdf, 0xa2f33668,
  0xbcb4666d, 0xb8757bda, 0xb5365d03, 0xb1f740b4
};

unsigned int
xcrc32(const unsigned char *buf, int len, unsigned int init)
{
  unsigned int crc = init;
  while (len--)
  {
    crc = (crc << 8) ^ crc32_table[((crc >> 24) ^ *buf) & 255];
    buf++;
  }
  return crc;
}

int ElinkSCmd::run(CmdCtx * p)
{
  if (m_modename == "slavedfu") {
    // set mode to slavedfu
    DFU_Switch2DFU(p);
  }
  else if (m_modename == "masterdfu") {
    // set mode to master dfu
    unsigned char a = 1;
    FUSetCommand(p, DFU_SET_MASTER_MODE, 1, &a);
  }
  else if (m_modename == "masterapp") {
    // set mode to master app
    unsigned char a = 2;
    FUSetCommand(p, DFU_SET_MASTER_MODE, 1, &a);
  }
  else if (m_modename == "slaveapp") {
    // set mode to slave app
    DFU_Switch2App(p);
  }
  return 0;
}

int ElinkBase::FUSetCommand(CmdCtx * p, unsigned int cmd, unsigned int len, unsigned char * data)
{
  int status = 0;
#if 1
  char fp[FEATURE_PACKET_LEN + 1];
  fp[0] = 0;
  fp[1] = cmd;
  fp[2] = len;
  memcpy(fp + 3, data, len);
  BOOLEAN ret;
  ret =  HidD_SetFeature((HANDLE)p->m_hid_dev, fp, FEATURE_PACKET_LEN + 1);
  return ret ? 0 : 1;
#else
  char fp[FEATURE_PACKET_LEN + 1];
  fp[0] = cmd;
  fp[1] = len;
  memcpy(fp + 2, data, len);
  HIDTrans dev;
  if (dev.open(p->m_dev))
    return -1;

  HIDReport report(&dev);
  status = report.write(fp, len + 2 , 0);
  return status;
#endif
}

int ElinkBase::FUGetCommand(CmdCtx * p, unsigned int cmd, unsigned int len, unsigned char * data)
{
  BOOLEAN ret;
  char fp[FEATURE_PACKET_LEN + 1];
  fp[0] = 0;
  fp[1] = cmd;
  fp[2] = len;
  ret = HidD_SetFeature((HANDLE)p->m_hid_dev, (char *)fp, FEATURE_PACKET_LEN + 1);
  if (!ret) return 1;

  fp[0] = 0;
  ret = HidD_GetFeature((HANDLE)p->m_hid_dev, (char*)fp, FEATURE_PACKET_LEN + 1);
  memcpy(data, fp + 1, len);
  return ret ? 0 : 1;
}

int ElinkBase::DFU_GetStatus_n_State(CmdCtx * p, unsigned char * status, unsigned char * state)
{
  unsigned char result[2];
  int i;
  result[0] = 0;
  result[1] = 0;
  Sleep(20);
  i = FUGetCommand(p, DFU_GET_STATUS, 2, &result[0]);
  *status = result[0];
  *state = result[1];
  return i;
}

int ElinkBase::DFU_GetInfo(CmdCtx * p, DFU_INFO_PACKET * dfu_info)
{
  int i;

  for (i = 0; i < sizeof(DFU_INFO_PACKET); i++) ((char*)dfu_info)[i] = 0;
  i = FUGetCommand(p, DFU_GET_INFO, sizeof(DFU_INFO_PACKET), (unsigned char*)dfu_info);

  return i;
}

uint8_t* TagInfo_Parse(uint8_t *tag, uint8_t* buf, void** pdata, uint8_t *len)
{
  if (len != NULL)
    *len = buf[0];
  if (tag != NULL)
    *tag = buf[1];
  if (pdata != NULL)
    *pdata = &buf[2];
  return buf + buf[0];
}

int ElinkBase::DFU_GetInfoTag(CmdCtx * p, unsigned char * dfu_info)
{
  int i;

  for (i = 0; i < FEATURE_DATA_LEN; i++) ((char*)dfu_info)[i] = 0;
  i = FUGetCommand(p, DFU_GET_INFO, FEATURE_DATA_LEN, dfu_info);
  return i;
}

int ElinkBase::DFU_EndUpgrade(CmdCtx * p)
{
  unsigned char a;
  return FUSetCommand(p, DFU_END_UPGRADE, 1, &a);
}

int ElinkBase::DFU_StartUpgrade(CmdCtx * p)
{
  unsigned char a;
  int ret = FUSetCommand(p, DFU_START_UPGRADE, 1, &a);
  return ret;
}

int ElinkBase::DFU_SendData(CmdCtx * p, unsigned char * databuf, int len)
{
  return FUSetCommand(p, DFU_SEND_DATA, len, databuf);
}

unsigned char ElinkBase::DFU_GetStatus(CmdCtx * p)
{
  unsigned char status, state;
  DFU_GetStatus_n_State(p, &status, &state);
  return status;
}

int ElinkBase::DFU_Verify(CmdCtx * p, unsigned int crc)
{
  return FUSetCommand(p, DFU_VERIFY, 4, (unsigned char*)&crc);
}

int ElinkBase::DFU_Switch2App(CmdCtx * p)
{
  unsigned char a;
  return FUSetCommand(p, DFU_SWITCH2APP, 1, &a);
}

int ElinkBase::DFU_Switch2DFU(CmdCtx * p)
{
  unsigned char a;
  return FUSetCommand(p, DFU_SWITCH2DFU, 1, &a);
}

int ElinkBase::DFU_SwitchPart(CmdCtx * p, unsigned char partid)
{
  return FUSetCommand(p, DFU_SWITCH_PART, 1, &partid);
}

int ElinkBase::DFU_Execute(CmdCtx * p, uint32_t address, uint32_t param)
{
  uint32_t data[2] = { address, param };
  return FUSetCommand(p, DFU_EXECUTE_ADDRESS, sizeof(data), (unsigned char *)&data[0]);
}

int ElinkBase::DFU_GetCustomStatus(CmdCtx * p, unsigned char * buf, int len)
{
  return FUGetCommand(p, 0x96, len, buf);
}

int ElinkBase::DFU_GetAppVersion(CmdCtx * p, unsigned char * buf, int len)
{
  return FUGetCommand(p, DFU_GET_APP_VERSION, len, buf);
}

int ElinkWriteCmd::run(CmdCtx * p)
{
  string_ex notifyMsg;
  uuu_notify nt;
  nt.type = uuu_notify::NOTIFY_CMD_INFO;

  uint32_t crc;
  unsigned int dfu_state = DFU_IDLE;
  unsigned int dfu_status = DFU_OK;

  shared_ptr<FileBuffer> buf = get_file_buffer(m_filename);
  if (!p) {
    notifyMsg.format("not able to access file %s\n", m_filename.c_str());
    set_last_err_string(notifyMsg);
    return -1;
  }

  notifyMsg.format("Start Upgrade = %s\r\n", m_filename.c_str());
  nt.str = (char *)notifyMsg.c_str();
  call_notify(nt);

  if (DFU_Switch2DFU(p) != 0) {
    notifyMsg.format("error to switch to DFU mode\n");
    set_last_err_string(notifyMsg);
    return -1;
  }

  if (0 == DFU_GetStatus_n_State(p, (unsigned char *)&dfu_status, (unsigned char *)&dfu_state)) {
    if (dfu_status == DFU_ERROR) {
      notifyMsg.format("elinkkvm is not in dfu mode\n");
      set_last_err_string(notifyMsg);
      DFU_EndUpgrade(p);
      return -1;
    }
  }

  if (0 != DFU_StartUpgrade(p)) {
    notifyMsg.format("Can not Send Start upgrade command. Exit!\n");
    set_last_err_string(notifyMsg);
    return -1;
  }

  int i = 5;
  while (i-- > 0) {
    if (DFU_GetStatus_n_State(p, (unsigned char *)&dfu_status, (unsigned char *)&dfu_state)) {
      notifyMsg.format("Get Status Fail. Exit!");
      set_last_err_string(notifyMsg);
      return -1;
    }
    if (dfu_status != DFU_PENDING) break;
  }

  if (dfu_state != DNLOAD) {
    notifyMsg.format("Device can not upgrade. Exit!");
    set_last_err_string(notifyMsg);
    return -1;
  }

  size_t offset = 0;
  size_t size = buf->size();
  size_t sendLen;

  nt.type = uuu_notify::NOTIFY_TRANS_SIZE;
  nt.total = size;
  call_notify(nt);

  while (offset < size) {
    sendLen = size - offset;
    if (sendLen > DATABUF_LEN)
      sendLen = DATABUF_LEN;
    if (DFU_SendData(p, buf->data() + offset, sendLen)) {
      DFU_EndUpgrade(p);
      notifyMsg.format("Send Data Fail. Exit!");
      set_last_err_string(notifyMsg);
      return -1;
    }
    else {
      if (DFU_GetStatus_n_State(p, (unsigned char *)&dfu_status, (unsigned char *)&dfu_state)) {
        notifyMsg.format("Send Data Fail. Exit!");
        set_last_err_string(notifyMsg);
        DFU_EndUpgrade(p);
        return -1;
      }
      else {
        while (dfu_status == DFU_PENDING) {
          if (DFU_GetStatus_n_State(p, (unsigned char *)&dfu_status, (unsigned char *)&dfu_state)) {
            notifyMsg.format("Get Status Fail. Exit!");
            set_last_err_string(notifyMsg);
            DFU_EndUpgrade(p);
            return -1;
          }
        }
      }
    }
    offset += sendLen;
    nt.type = uuu_notify::NOTIFY_TRANS_POS;
    nt.total = offset;
    call_notify(nt);
  }
  DFU_EndUpgrade(p);
  while ((dfu_status = DFU_GetStatus(p)) == DFU_PENDING);

  nt.type = uuu_notify::NOTIFY_CMD_INFO;
  notifyMsg.format("Status After End Upgrade = %d\r\n",dfu_status);
  nt.str = (char *)notifyMsg.c_str();
  call_notify(nt);
  crc = xcrc32(buf->data(), size, 0xFFFFFFFF);
  DFU_Verify(p, crc);

  while ((dfu_status = DFU_GetStatus(p)) == DFU_PENDING);
  if (dfu_status != DFU_OK)
  {
    notifyMsg.format("Verify Fail. %x Exit!",crc);
    set_last_err_string(notifyMsg);
    return -1;
  }
  nt.type = uuu_notify::NOTIFY_CMD_INFO;
  notifyMsg.format("crc verify success = %x\r\n", crc);
  nt.str = (char *)notifyMsg.c_str();
  call_notify(nt);
  return 0;
}

int ElinkInfoCmd::run(CmdCtx * p)
{
  int isExit = 0;
  string_ex notifyMsg;
  string statusMsg;
  unsigned char dfuInfo[FEATURE_DATA_LEN], dlen;
  unsigned char tag, len, *data, partId;
  DFU_INFO_PACKET dfu_info;
  uuu_notify nt;
  nt.type = uuu_notify::NOTIFY_CMD_INFO;

  DFU_Switch2DFU(p);

  while (!isExit) {
    if (DFU_GetInfoTag(p, dfuInfo) != 0) {
      notifyMsg.format("Error getting InfoTag\r\n");
      set_last_err_string(notifyMsg);
      return -1;
    }
    unsigned char* buf = (unsigned char*)dfuInfo;
    buf = TagInfo_Parse(&tag, buf, (void**)&data, &len);
    if (tag == TAGINFO_DEFAULT_START && len == 3) {
      unsigned int version = 0xDF25DF25;
      memcpy(&dlen, data, sizeof(dlen));
      while (dlen > 0) {
        buf = TagInfo_Parse(&tag, buf, (void**)&data, &len);
        if (buf == NULL) break;
        switch (tag)
        {
        case DFU_INFO_SIGN:
          if (memcmp(data, &version, 4) != 0) dlen = 0;
          break;
        case DFU_INFO_VERSION: 
        {
          memcpy(&dfu_info.BootCodeVersion, data, sizeof(dfu_info.BootCodeVersion));
          notifyMsg.format("Bootloader version %x\r\n", dfu_info.BootCodeVersion);
          statusMsg += notifyMsg;
          break;
        }
        case DFU_INFO_UID_STR:
        {
          memcpy(&dfu_info.UID[0], data, min(sizeof(dfu_info.UID[0]) * 3, len - 2));
          notifyMsg.format("UID: %x-%x-%x\r\n", dfu_info.UID[0], dfu_info.UID[1], dfu_info.UID[2]);
          statusMsg += notifyMsg;
          break;
        }
        case DFU_INFO_PART_ID:
        if(m_showDetail) {
          memcpy(&partId, data, sizeof(partId));
          notifyMsg.format("ID:%02d,\t", partId);
          statusMsg += notifyMsg;
        }
        break;
        case DFU_INFO_PART_NAME:
        if (m_showDetail)  {
          char bk = data[len - 2];
          data[len - 2] = 0;
          notifyMsg.format("Name:%s,\t", data);
          data[len - 2] = bk;
          statusMsg += notifyMsg;
        }
        break;
        case DFU_INFO_PART_SIZE: 
        if (m_showDetail) {
          notifyMsg.format("Size: 0x%08x\r\n", *(uint32_t*)data);
          statusMsg += notifyMsg;
        }
        break;
        case TAGINFO_DEFAULT_END:
          isExit = 1;
          break;
        }
        dlen -= len;
      }
    }
  }
  nt.str = (char *)statusMsg.c_str();
  call_notify(nt);
  return 0;
}

int ElinkExecCmd::run(CmdCtx * p)
{
  string_ex notifyMsg;
  uuu_notify nt;
  nt.type = uuu_notify::NOTIFY_CMD_INFO;

  uint32_t crc;
  unsigned int dfu_state = DFU_IDLE;
  unsigned int dfu_status = DFU_OK;

  shared_ptr<FileBuffer> buf = get_file_buffer(m_filename);
  if (!p) {
    notifyMsg.format("not able to access file %s\n", m_filename.c_str());
    set_last_err_string(notifyMsg);
    return -1;
  }

  if (DFU_Switch2DFU(p) != 0) {
    notifyMsg.format("error to switch to DFU mode\n");
    set_last_err_string(notifyMsg);
    return -1;
  }

  if (0 == DFU_GetStatus_n_State(p, (unsigned char *)&dfu_status, (unsigned char *)&dfu_state)) {
    if (dfu_status == DFU_ERROR) {
      notifyMsg.format("elinkkvm is not in dfu mode\n");
      set_last_err_string(notifyMsg);
      DFU_EndUpgrade(p);
      return -1;
    }
  }

  if (0 != DFU_SwitchPart(p,5)) {
    notifyMsg.format("Can not switch partition. Exit!\n");
    set_last_err_string(notifyMsg);
    return -1;
  }

  if (0 != DFU_StartUpgrade(p)) {
    notifyMsg.format("Can not Send Start upgrade command. Exit!\n");
    set_last_err_string(notifyMsg);
    return -1;
  }

  int i = 5;
  while (i-- > 0) {
    if (DFU_GetStatus_n_State(p, (unsigned char *)&dfu_status, (unsigned char *)&dfu_state)) {
      notifyMsg.format("Get Status Fail. Exit!");
      set_last_err_string(notifyMsg);
      return -1;
    }
    if (dfu_status != DFU_PENDING) break;
  }

  if (dfu_state != DNLOAD) {
    notifyMsg.format("Device can not upgrade. Exit!");
    set_last_err_string(notifyMsg);
    return -1;
  }

  size_t offset = 0;
  size_t size = buf->size();
  size_t sendLen;

  nt.type = uuu_notify::NOTIFY_TRANS_SIZE;
  nt.total = size;
  call_notify(nt);

  while (offset < size) {
    sendLen = size - offset;
    if (sendLen > DATABUF_LEN)
      sendLen = DATABUF_LEN;
    if (DFU_SendData(p, buf->data() + offset, sendLen)) {
      DFU_EndUpgrade(p);
      notifyMsg.format("Send Data Fail. Exit!");
      set_last_err_string(notifyMsg);
      return -1;
    }
    else {
      if (DFU_GetStatus_n_State(p, (unsigned char *)&dfu_status, (unsigned char *)&dfu_state)) {
        notifyMsg.format("Send Data Fail. Exit!");
        set_last_err_string(notifyMsg);
        DFU_EndUpgrade(p);
        return -1;
      }
      else {
        while (dfu_status == DFU_PENDING) {
          if (DFU_GetStatus_n_State(p, (unsigned char *)&dfu_status, (unsigned char *)&dfu_state)) {
            notifyMsg.format("Get Status Fail. Exit!");
            set_last_err_string(notifyMsg);
            DFU_EndUpgrade(p);
            return -1;
          }
        }
      }
    }
    offset += sendLen;
    nt.type = uuu_notify::NOTIFY_TRANS_POS;
    nt.total = offset;
    call_notify(nt);
  }
  DFU_EndUpgrade(p);
  while ((dfu_status = DFU_GetStatus(p)) == DFU_PENDING);

  crc = xcrc32(buf->data(), size, 0xFFFFFFFF);
  DFU_Verify(p, crc);

  while ((dfu_status = DFU_GetStatus(p)) == DFU_PENDING);
  if (dfu_status != DFU_OK)
  {
    notifyMsg.format("Verify Fail. Exit!");
    set_last_err_string(notifyMsg);
    return -1;
  }

  if (0 != DFU_Execute(p, 0x20003c29,0)) {
    notifyMsg.format("Can not exec exit. Exit!\n");
    set_last_err_string(notifyMsg);
    return -1;
  }

  if (m_readLen > 0) {
    vector<uint8_t> retData(m_readLen);
    if (0 != DFU_GetCustomStatus(p, (unsigned char *)&retData.front(), m_readLen)) {
      notifyMsg.format("Can not exec exit. Exit!\n");
      set_last_err_string(notifyMsg);
      return -1;
    }
    nt.type = uuu_notify::NOTIFY_CMD_INFO;
    string retString = m_filename;
    retString.append(" ");
    for (int i = 0; i < m_readLen; i++) {
      notifyMsg.format("%02x", retData[i]);
      retString += notifyMsg;
    }
    retString.append("\r\n");
    nt.str = (char *)retString.c_str();
    call_notify(nt);
  }
  return 0;
}

int ElinkVersionCmd::run(CmdCtx * p)
{
  string_ex notifyMsg;
  string statusMsg;
  uuu_notify nt;
  nt.type = uuu_notify::NOTIFY_CMD_INFO;

  vector<uint8_t> retData(8);
  if (0 != DFU_GetAppVersion (p, (unsigned char *)&retData.front(), 8)) {
    notifyMsg.format("Can not exec exit. Exit!\n");
    set_last_err_string(notifyMsg);
    return -1;
  }
  nt.type = uuu_notify::NOTIFY_CMD_INFO;
  string retString("slavever");
  retString.append(" ");
  for (int i = 0; i < 8; i++) {
    notifyMsg.format("%02x", retData[i]);
    retString += notifyMsg;
  }
  retString.append("\r\n");
  nt.str = (char *)retString.c_str();
  call_notify(nt);
  return 0;
}
