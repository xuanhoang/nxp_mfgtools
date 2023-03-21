#pragma once

#include "cmd.h"

typedef struct _DFU_Info_ {
  unsigned long sign;
  //unsigned long PIN;
  unsigned long BootCodeVersion;
  unsigned long UID[4];
  unsigned long userflashsize;
} DFU_INFO_PACKET;

class ElinkBase {
protected:
  int FUSetCommand(CmdCtx *p, unsigned int cmd, unsigned int len, unsigned char * data);
  int FUGetCommand(CmdCtx *p, unsigned int cmd, unsigned int len, unsigned char * data);
  int DFU_GetStatus_n_State(CmdCtx *p, unsigned char *status, unsigned char* state);
  int DFU_GetInfo(CmdCtx *p, DFU_INFO_PACKET* dfu_info);
  int DFU_GetInfoTag(CmdCtx *p, unsigned char * dfu_info);
  int DFU_EndUpgrade(CmdCtx *p);
  int DFU_StartUpgrade(CmdCtx *p);
  int DFU_SendData(CmdCtx *p, unsigned char* databuf, int len);
  unsigned char DFU_GetStatus(CmdCtx *p);
  int DFU_Verify(CmdCtx *p, unsigned int crc);
  int DFU_Switch2App(CmdCtx *p);
  int DFU_Switch2DFU(CmdCtx *p);
  int DFU_SwitchPart(CmdCtx *p, unsigned char partid);
  int DFU_Execute(CmdCtx *p, uint32_t address, uint32_t param);
  int DFU_GetCustomStatus(CmdCtx *p, unsigned char *buf,int len);
  int DFU_GetAppVersion(CmdCtx *p, unsigned char *buf, int len);
};

class ElinkSCmd : public CmdBase, public ElinkBase
{
public:
  std::string m_modename;

  ElinkSCmd(char *cmd) :CmdBase(cmd)
  {
    insert_param_info("mode", nullptr, Param::Type::e_null);
    insert_param_info("-n", &m_modename, Param::Type::e_string);
  }
  int run(CmdCtx *p) override;
};

class ElinkWriteCmd : public CmdBase, public ElinkBase
{
public:
  std::string m_filename;

  ElinkWriteCmd(char *cmd) :CmdBase(cmd)
  {
    insert_param_info("write", nullptr, Param::Type::e_null);
    insert_param_info("-f", &m_filename, Param::Type::e_string_filename);
  }
  int run(CmdCtx *p) override;
};

class ElinkExecCmd : public CmdBase, public ElinkBase
{
public:
  std::string m_filename;
  uint32_t m_readLen;
  ElinkExecCmd(char *cmd) :CmdBase(cmd), m_readLen(0)
  {
    insert_param_info("exec", nullptr, Param::Type::e_null);
    insert_param_info("-f", &m_filename, Param::Type::e_string_filename);
    insert_param_info("-r", &m_readLen, Param::Type::e_uint32);
  }
  int run(CmdCtx *p) override;
};

class ElinkInfoCmd : public CmdBase, public ElinkBase
{
public:
  std::string m_filename;
  bool m_showDetail;
  ElinkInfoCmd(char *cmd) :CmdBase(cmd),m_showDetail(false)
  {
    insert_param_info("info", nullptr, Param::Type::e_null);
    insert_param_info("-l", &m_showDetail, Param::Type::e_bool);
  }
  int run(CmdCtx *p) override;
};

class ElinkVersionCmd : public CmdBase, public ElinkBase
{
public:
  ElinkVersionCmd(char *cmd) :CmdBase(cmd)
  {
    insert_param_info("version", nullptr, Param::Type::e_null);
  }
  int run(CmdCtx *p) override;
};