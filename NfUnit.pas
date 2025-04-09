unit NfUnit;

interface

uses
  Windows, SysUtils, WinSock2, Classes, WinSvc, MemoryModule, NethelperAPI;

const
  nfscname = 'nethelper';

type
  in_addr6 = record
    addr: array [0..15] of byte;
  end;
  PInAddr6 = ^in_addr6;

  SOCKADDR_IN6 = record
    sin_family: Smallint;
    sin_port: u_short;
    sin_flowinfo: dword;
    sin_addr: in_addr6;
    sin_scope_id: dword;
  end;
  PSockAddrIn6 = ^SOCKADDR_IN6;

  tcp_keepalive=record
    onoff,
    keepalivetime,
    keepaliveinterval: ULONG;
  end;

  PNF_UDP_OPTIONS = ^NF_UDP_OPTIONS;

  TMapSocket=class
  private
    fHost: AnsiString;
    fPort: AnsiString;

    fid: ENDPOINT_ID;

    fAcceptThread, fAcceptThreadID: DWORD;
    fHandleThread, fHandleThreadID: DWORD;
    fSocket5Thread, fSocket5ThreadID: DWORD;
    fUDPThread, fUDPThreadID: DWORD;

    fSocket, fSocket5, fUDPSocket, fClientSocket: TSocket;

    fUDPRAddr: SOCKADDR_IN6;
  public
    var
      ID,PID,ProcName,HandleMode: String;
      fInfo: NF_TCP_CONN_INFO;
      fInfoUDP: NF_UDP_CONN_INFO;
      fUDPOption: PNF_UDP_OPTIONS;
      ListenPort: WORD;
      UP, DL: Int64;

    constructor Create(Host: AnsiString; Port: AnsiString);
    destructor Destroy; override;

    function HandleTCP(id: ENDPOINT_ID; info: NF_TCP_CONN_INFO): Boolean;
    function HandleUDP(id: ENDPOINT_ID; info: NF_UDP_CONN_INFO): Boolean;

    function ConnectS5: Boolean;
    function HandshakeS5: Boolean;
    function SplitAddr(Addr: PSockAddrIn6): Boolean;
    function ConnectTCP: Boolean;

    function UDPAssociate: Boolean;
    function CreateUDP(UDPOption: Pointer): Boolean;
    function UDPRead(target: PSockAddrIn6; buffer: PAnsiChar; length: Integer): Integer;
    function UDPSend(target: PSockAddrIn6; buffer: PAnsiChar; length: Integer): Integer;
  end;

  function InstallNFDriver: Boolean;
  function UnNFDriver: Boolean;

  function SetNfDriver(Socket5Host: AnsiString; Port: AnsiString): Boolean;
  procedure StopNFDriver;

  procedure AddPTarget(Val: String);
  procedure AddPTargets(Val: TStrings);

  function ConvertIP(addr: PSOCKADDR): AnsiString;

var
  NFConnects: TStringList;
  NFTotalUP, NFTotalDL: Int64;

implementation

{$I nethelp.inc}
{$I nethelperdll.inc}

const
  SOCKS5_VER = #$05;
  SOCKS5_AUTH_NONE = #$00;
  SOCKS5_AUTH_GSSAPI = #$01;
  SOCKS5_AUTH_PASS = #$02;
  SOCKS5_AUTH_NO_METHODS = #$FF;

  SOCKS5_REQ_VER = #$05;
  SOCKS5_REQ_CMD_CONNECT = #$01;
  SOCKS5_REQ_CMD_BIND = #$02;
  SOCKS5_REQ_CMD_UDP = #$03;

  SOCKS5_REQ_RSV = #$00;

  SOCKS5_REQ_ATYP_IP4 = #$01;
  SOCKS5_REQ_ATYP_DOMAIN = #$03;
  SOCKS5_REQ_ATYP_IP6 = #$04;

  SOCKS5_REP_VER = #$05;
  SOCKS5_REP_REP_OK = #$00;
  SOCKS5_REP_REP_GENFAIL = #$01;
  SOCKS5_REP_REP_CONN_NOT_ALLOWED = #$02;
  SOCKS5_REP_REP_NET_UNREACH = #$03;
  SOCKS5_REP_REP_HOST_UNREACH = #$04;
  SOCKS5_REP_REP_CONN_REFUSED = #$05;
  SOCKS5_REP_REP_TTL_EXPIRED = #$06;
  SOCKS5_REP_REP_CMD_NOT_SUPP = #$07;
  SOCKS5_REP_REP_ATYPE_NOT_SUPP = #$08;
  SOCKS5_REP_RSV = #$00;
  SOCKS5_REP_ATYP_IP4 = #$01;
  SOCKS5_REP_ATYP_DOMAIN = #$03;
  SOCKS5_REP_ATYP_IP6 = #$04;

  IPV6_V6ONLY = 27;

var
  eh: NF_EventHandler;
  err: Integer;
  fActive: Boolean;
  fTagDirs: TStringList;
  FSHost, FSPort: AnsiString;
  NFSFILE: String;

  wd : WSAData;
  mDLL: TMemoryModule;

  nf_init: function (driverName : PAnsiChar; var pHandler : NF_EventHandler) : integer; cdecl;
  nf_free: procedure (); cdecl;

  nf_registerDriver: function (driverName : PAnsiChar): integer; cdecl;
  nf_unRegisterDriver: function (driverName : PAnsiChar): integer; cdecl;

  nf_tcpPostSend: function (id : ENDPOINT_ID; buf : PAnsiChar; len : Longword): integer; cdecl;
  nf_tcpPostReceive: function (id : ENDPOINT_ID; buf : PAnsiChar; len : Longword): integer; cdecl;
  //nf_tcpClose: function (id : ENDPOINT_ID): integer; cdecl;

  nf_udpPostSend: function (id : ENDPOINT_ID; remoteAddress : PAnsiChar; buf : PAnsiChar; len : Longword; options : pointer): integer; cdecl;
  nf_udpPostReceive: function (id : ENDPOINT_ID; remoteAddress : PAnsiChar; buf : PAnsiChar; len : Longword; options : pointer): integer; cdecl;

  nf_addRule: function (var rule : NF_RULE; toHead : integer): integer; cdecl;
  nf_deleteRules: function (): integer; cdecl;

  nf_tcpDisableFiltering: function (id : ENDPOINT_ID): integer; cdecl;
  //nf_udpDisableFiltering: function (id : ENDPOINT_ID): integer; cdecl;

  nf_adjustProcessPriviledges: procedure (); cdecl;
  nf_getProcessNameW: function (processId : Longword; buf : PWideChar; len : integer) : boolean;  cdecl;
  nf_getProcessNameFromKernel: function (processId : Longword; buf : PWideChar; len : integer) : boolean; cdecl;

function WSAStringToAddressA(AddressString: PAnsiChar; AddressFamily: Integer;
  lpProtocolInfo: Pointer; lpAddress: Pointer; var lpAddressLength: Longword)
  : Integer; stdcall; external 'ws2_32.dll';

function WSAAddressToStringA(lpsaAddress: Pointer; dwAddressLength: Longword;
  lpProtocolInfo: Pointer; lpszAddressString: PAnsiChar;
  var lpdwAddressStringLength: Longword): Integer; stdcall;
  external 'ws2_32.dll';

function WSAConnectByName(s: TSocket; nodename, servicename: PAnsiChar; LocalAddressLength: PDWORD;
  LocalAddress: PSockAddr; RemoteAddressLength: PDWORD; RemoteAddress: PSockAddr;
  timeout: Ptimeval; Reserved: LPWSAOVERLAPPED): BOOL; stdcall; external 'ws2_32.dll' name 'WSAConnectByNameA';

function recvfrom(s: TSocket; var buf; len, flags: Integer; from: PSockAddr;
  fromlen: PInteger): Integer; stdcall;
  external 'ws2_32.dll' name 'recvfrom';

function SysDir:String;
var
 S: Array [0..255] of Char;
begin
  GetSystemDirectory(S,255);
  Result:=S;
end;

function TempDir:String;
var
 S: Array [0..255] of Char;
begin
  GetTempPath(255,s);
  Result:=S;
end;

procedure WriteSySFile;
var
  hFile: THandle;
  wSize, rSize: DWORD;
begin
  Windows.DeleteFile(PChar(SysDir+'\drivers\'+NFSFILE));
  Windows.DeleteFile(PChar(TempDir+NFSFILE));

  hFile:=CreateFile(PChar(TempDir+NFSFILE),GENERIC_WRITE,0,nil,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,0);
  wSize:=SizeOf(nethelper);
  WriteFile(hFile,nethelper,wSize,rSize,nil);
  CloseHandle(hFile);

  Windows.CopyFile(PChar(TempDir+'\'+NFSFILE),PChar(SysDir+'\drivers\'+NFSFILE),False);
  Windows.DeleteFile(PChar(TempDir+NFSFILE));
end;

procedure ServiceCtl(sService: string; Start: Boolean=true);
var
  schm, schs: SC_Handle;
  arg: Pchar;
  state: SERVICE_STATUS;
begin
  schm := OpenSCManager(nil, Nil, SC_MANAGER_CONNECT);
  if (schm > 0) then
  begin
    schs := OpenService(schm, PChar(sService), SERVICE_START or SERVICE_STOP);
    if (schs > 0) then
    begin
      if Start then
        StartService(schs,0,arg)
      else
        ControlService(schs,SERVICE_CONTROL_STOP,state);
      CloseServiceHandle(schs);
    end;
    CloseServiceHandle(schm);
  end;
end;

function InstallNFDriver: Boolean;
//var
//  NFdrvFile: String;
begin
  Result:=False;
  if fActive then exit;
  nf_adjustProcessPriviledges();
  //NFdrvFile:=GetCurrentDir+'\'+NFSFILE;
  //if Sysutils.FileExists(NFdrvFile) then
  //begin
    //Windows.CopyFile(PChar(NFdrvFile),PChar(SysDir+'\drivers\'+nfscfile),False);
    WriteSySFile;
    Result:=nf_registerDriver(nfscname)<>-1;
    ServiceCtl(nfscname);
  //end;
end;

function UnNFDriver: Boolean;
begin
  nf_adjustProcessPriviledges();
  StopNFDriver;
  ServiceCtl(nfscname,false);
  Result:=nf_unRegisterDriver(nfscname)<>-1;
  Windows.DeleteFile(PChar(SysDir+'\drivers\'+NFSFILE));
end;

procedure Log(fmt: string; args: array of const);
var
  buf: string;
begin
  buf := '[NFUnit] ' + Format(fmt, args);
  //WriteLn(buf);
  OutputDebugString(PChar(buf));
end;

procedure IN6_SET_ADDR_LOOPBACK(a: PInAddr6);
begin
  ZeroMemory(a, 16);
  a.addr[15] := 1;
end;

function IN6_IS_LOOPBACK(a: PInAddr6): Boolean;
var
  I: Integer;
begin
  Result:=False;
  for I:=0 to 14 do
    if a.addr[I]<>0 then Exit;
  if a.addr[15]<>1 then Exit;
  Result:=True;
end;

function IN6_IS_ANY(a: PInAddr6): Boolean;
var
  I: Integer;
begin
  Result:=False;
  for I:=0 to SizeOf(in_addr6) do
    if a.addr[I]<>0 then Exit;
  Result:=True;
end;

function ConvertIP(addr: PSOCKADDR): AnsiString;
var
  buf: Array [0..255] of AnsiChar;
	bufferLength: DWORD;
begin
  bufferLength := 255;
  FillChar(buf,256,0);

	if (addr.sa_family = AF_INET) then
		WSAAddressToStringA(addr, sizeof(SOCKADDR_IN), nil, buf, bufferLength)
	else
		WSAAddressToStringA(addr, SizeOf(SOCKADDR_IN6), nil, buf, bufferLength);

	Result:=buf;
end;

function GetProcessName(pid: DWORD): String;
var
  Pn,Pf: Array [0..MAX_PATH-1] of Char;
begin
  Result:='';
  FillChar(Pn,MAX_PATH,0);
  FillChar(Pf,MAX_PATH,0);
  if nf_getProcessNameFromKernel(pid,Pn,MAX_PATH)=false then
    nf_getProcessNameW(pid,Pn,MAX_PATH);

  if Pn<>'' then GetLongPathNameW(Pn,Pf,MAX_PATH);
  Result:=Pf;
end;

function CheckTarget(Val: String): Boolean;
var
  I: Integer;
begin
  Result:=False;
  for I:=0 to fTagDirs.Count-1 do
    if (AnsiPos(fTagDirs[I], Val)>0) or (Val=fTagDirs[I]) then
    begin
      Result:=True;
      Break;
    end;
end;

procedure DeleteMapSocket(MapSocket: TMapSocket);
var
  Idx: Integer;
begin
  if Not Assigned(MapSocket) then Exit;
  try
    Idx:=NFConnects.IndexOf(MapSocket.ID);
    if Idx>=0 then NFConnects.Delete(Idx);
    if Assigned(MapSocket) then MapSocket.Free;
  except
  end;
  //Log('MapSocket Delete [%d]', [Idx]);
end;

procedure DeleteMapSocketID(ID: ENDPOINT_ID);
var
  Idx: Integer;
  IdStr: String;
  MapSocket: TMapSocket;
begin
  IdStr:=IntToStr(ID);
  try
    Idx:=NFConnects.IndexOf(IdStr);
    if Idx>=0 then
    begin
      MapSocket:=TMapSocket(NFConnects.Objects[Idx]);
      if Assigned(MapSocket) then MapSocket.Free;
      NFConnects.Delete(Idx);
    end;
  except
  end;
  //Log('MapSocket Delete [%d]', [Idx]);
end;

////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////

procedure threadStart(); cdecl;
begin
end;

procedure threadEnd(); cdecl;
begin
end;

procedure tcpConnectRequest(id: ENDPOINT_ID; var pConnInfo: NF_TCP_CONN_INFO); cdecl;
var
  pAddr: PSockAddrIn;
  pAddr6: PSockAddrIn6;
  Pn, IdStr: String;
  MapSocket: TMapSocket;
begin
  pAddr := @pConnInfo.remoteAddress;
  pAddr6 := @pConnInfo.remoteAddress;

  if GetCurrentProcessID=pConnInfo.processId then
  begin
    nf_tcpDisableFiltering(id);
    exit;
  end;

  if (pAddr.sin_family = AF_INET) then
    if pAddr.sin_addr.S_addr = htonl(INADDR_LOOPBACK) then Exit;
  if (pAddr.sin_family = AF_INET6) then
    if IN6_IS_LOOPBACK(@pAddr6.sin_addr) then Exit;

  IdStr:=IntToStr(id);
  Pn:=GetProcessName(pConnInfo.processId);

  if CheckTarget(Pn) then
  begin
    Log('TCP [%d][%s] [%s]->[%s]',[id,Pn,ConvertIP(PSOCKADDR(@pConnInfo.localAddress)),ConvertIP(PSOCKADDR(pAddr))]);
    if NFConnects.IndexOf(IdStr)=-1 then
    begin
      MapSocket:=TMapSocket.Create(FSHost,FSPort);
      MapSocket.ProcName:=Pn;
      MapSocket.ID:=IdStr;
      MapSocket.PID:=IntToStr(pConnInfo.processId);
      MapSocket.HandleTCP(id,pConnInfo);

      if (pAddr.sin_family = AF_INET) then
      begin
        pAddr.sin_addr.S_addr:=htonl(INADDR_LOOPBACK);
        pAddr.sin_port:=MapSocket.ListenPort;
      end else begin
        IN6_SET_ADDR_LOOPBACK(@pAddr6.sin_addr);
        pAddr6.sin_port:=MapSocket.ListenPort;
      end;

      NFConnects.AddObject(IdStr,MapSocket);
    end;
  end else begin
    //Log('DisableFiltering [%d][%s]',[id,Pn]);
    nf_tcpDisableFiltering(id);
  end;
end;

procedure tcpConnected(id: ENDPOINT_ID; var pConnInfo: NF_TCP_CONN_INFO); cdecl;
begin
end;

procedure tcpClosed(id: ENDPOINT_ID; var pConnInfo: NF_TCP_CONN_INFO); cdecl;
begin
end;

procedure tcpReceive(id: ENDPOINT_ID; buf: PAnsiChar; len: Integer); cdecl;
begin
  nf_tcpPostReceive(id, buf, len);
end;

procedure tcpSend(id: ENDPOINT_ID; buf: PAnsiChar; len: Integer); cdecl;
begin
  nf_tcpPostSend(id, buf, len);
end;

procedure tcpCanReceive(id: ENDPOINT_ID); cdecl;
begin
end;

procedure tcpCanSend(id: ENDPOINT_ID); cdecl;
begin
end;

procedure udpCreated(id: ENDPOINT_ID; var pConnInfo: NF_UDP_CONN_INFO); cdecl;
//var
//  Pn, IdStr: String;
//  MapSocket: TMapSocket;
begin
//  if GetCurrentProcessID=pConnInfo.processId then
//  begin
//    nf_udpDisableFiltering(id);
//    exit;
//  end;
//
//  IdStr:=IntToStr(id);
//  Pn:=GetProcessName(pConnInfo.processId);
//
//  if CheckTarget(Pn) then
//  begin
//    Log('UDP [%d][%s] [%s]',[id,Pn,ConvertIP(PSOCKADDR(@pConnInfo.localAddress))]);
//    if NFConnects.IndexOf(IdStr)=-1 then
//    begin
//      MapSocket:=TMapSocket.Create(FSHost,FSPort);
//      MapSocket.ProcName:=Pn;
//      MapSocket.ID:=IdStr;
//      MapSocket.HandleUDP(id,pConnInfo);
//
//      NFConnects.AddObject(IdStr,MapSocket);
//    end;
//  end else begin
//    //Log('DisableFiltering [%d][%s]',[id,Pn]);
//    nf_udpDisableFiltering(id);
//  end;
end;

procedure udpConnectRequest(id: ENDPOINT_ID; var pConnReq: NF_UDP_CONN_REQUEST); cdecl;
begin
end;

procedure udpClosed(id: ENDPOINT_ID; var pConnInfo: NF_UDP_CONN_INFO); cdecl;
begin
  //DeleteMapSocketID(id);
  //Log('[%d] udpClosed', [id]);
end;

procedure udpReceive(id: ENDPOINT_ID; remoteAddress: PAnsiChar; buf: PAnsiChar; len: Integer; options: Pointer); cdecl;
begin
  nf_udpPostReceive(id, remoteAddress, buf, len, options);
end;

procedure udpSend(id: ENDPOINT_ID; remoteAddress: PAnsiChar; buf: PAnsiChar; len: Integer; options: Pointer); cdecl;
//var
//  IdStr: String;
//  Idx: Integer;
//  MapSocket: TMapSocket;
//  Buff: Array [0..1457] of Byte;
//  addr: SOCKADDR_IN6;
//  pAddr: PSockAddrIn;
//  pAddr6: PSockAddrIn6;
begin
  nf_udpPostSend(id, remoteAddress, buf, len, options);

//  pAddr := @remoteAddress;
//  pAddr6 := @remoteAddress;
//
//  if (pAddr.sin_family = AF_INET) then
//    if pAddr.sin_addr.S_addr = htonl(INADDR_LOOPBACK) then
//    begin
//      nf_udpPostSend(id, remoteAddress, buf, len, options);
//      exit;
//    end;
//  if (pAddr.sin_family = AF_INET6) then
//    if IN6_IS_LOOPBACK(@pAddr6.sin_addr) then
//    begin
//      nf_udpPostSend(id, remoteAddress, buf, len, options);
//      exit;
//    end;
//
//  IdStr:=IntToStr(id);
//  Idx:=NFConnects.IndexOf(IdStr);
//  if Idx=-1 then
//  begin
//    nf_udpPostSend(id, remoteAddress, buf, len, options);
//    exit;
//  end;
//
//  MapSocket:=TMapSocket(NFConnects.Objects[Idx]);
//  if Not Assigned(MapSocket) then
//  begin
//    nf_udpPostSend(id, remoteAddress, buf, len, options);
//    exit;
//  end;
//
//  if PSockAddrIn(remoteAddress).sin_family=AF_INET then
//    if htons(PSockAddrIn(remoteAddress).sin_port)=53 then
//    begin
//      Log('UDP [%d][%s] FixDNS [%s]->[208.67.222.222]',[id,MapSocket.ProcName,ConvertIP(PSOCKADDR(remoteAddress))]);
//      PSockAddrIn(remoteAddress).sin_addr.S_addr:=inet_addr('208.67.222.222');
//    end;
//
//  if MapSocket.UDPAssociate then
//  begin
//    MapSocket.CreateUDP(options);
//    MapSocket.UDPSend(PSockAddrIn6(remoteAddress),buf,len);
//    Inc(MapSocket.UP,len);
//    Inc(NFTotalUP,len);
//  end else begin
//    nf_udpPostSend(id, remoteAddress, buf, len, options);
//  end;
end;

procedure udpCanReceive(id: ENDPOINT_ID); cdecl;
begin
end;

procedure udpCanSend(id: ENDPOINT_ID); cdecl;
begin
end;

////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////

procedure AddPTarget(Val: String);
begin
  if fTagDirs.IndexOf(Val)=-1 then fTagDirs.Add(Val);
end;

procedure AddPTargets(Val: TStrings);
var
  I: Integer;
begin
  for I:=0 to Val.Count-1 do
  begin
    if fTagDirs.IndexOf(Val[I])=-1 then fTagDirs.Add(Val[I]);
  end;
end;

function SetNfDriver(Socket5Host: AnsiString; Port: AnsiString): Boolean;
var
  rule : NF_RULE;
begin
  Result:=False;
  if fActive then Exit;
  NFConnects.Clear;
  fTagDirs.Clear;

  FSHost:=Socket5Host;
  FSPort:=Port;

  eh.threadStart := threadStart;
  eh.threadEnd := threadEnd;

  eh.tcpConnectRequest := tcpConnectRequest;
  eh.tcpConnected := tcpConnected;
  eh.tcpClosed := tcpClosed;
  eh.tcpReceive := tcpReceive;
  eh.tcpSend := tcpSend;
  eh.tcpCanReceive := tcpCanReceive;
  eh.tcpCanSend := tcpCanSend;

  eh.udpCreated := udpCreated;
  eh.udpConnectRequest := udpConnectRequest;
  eh.udpClosed := udpClosed;
  eh.udpReceive := udpReceive;
  eh.udpSend := udpSend;
  eh.udpCanReceive := udpCanReceive;
  eh.udpCanSend := udpCanSend;

  nf_adjustProcessPriviledges();
  err := nf_init(nfscname, eh);
  if err = NF_STATUS_FAIL then
  begin
    InstallNFDriver;
    err := nf_init(nfscname, eh);
  end;
  if (err = NF_STATUS_SUCCESS) then
  begin
    nf_deleteRules();

    //LoopBack
		FillChar(rule, sizeof(rule), 0);
		rule.ip_family := AF_INET;
    inet_pton(AF_INET, '127.0.0.1', @rule.remoteIpAddress);
    inet_pton(AF_INET, '255.0.0.0', @rule.remoteIpAddressMask);
    rule.filteringFlag := NF_ALLOW;
    nf_addRule(rule, 1);

    FillChar(rule, sizeof(rule), 0);
		rule.ip_family := AF_INET6;
    rule.remoteIpAddress[15] := 1;
    FillChar(rule.remoteIpAddressMask, sizeof(rule.remoteIpAddressMask), $FF);
    rule.filteringFlag := NF_ALLOW;
    nf_addRule(rule, 1);

    //TCP
    FillChar(rule, sizeof(rule), 0);
    rule.ip_family := AF_INET;
    rule.protocol := IPPROTO_TCP;
    rule.direction := NF_D_OUT;
    rule.filteringFlag := NF_INDICATE_CONNECT_REQUESTS;
    nf_addRule(rule, 1);

    FillChar(rule, sizeof(rule), 0);
    rule.ip_family := AF_INET6;
    rule.protocol := IPPROTO_TCP;
    rule.direction := NF_D_OUT;
    rule.filteringFlag := NF_INDICATE_CONNECT_REQUESTS;
    nf_addRule(rule, 1);

		FillChar(rule, sizeof(rule), 0);
		rule.ip_family := AF_INET;
    inet_pton(AF_INET, '192.168.0.0', @rule.remoteIpAddress);
    inet_pton(AF_INET, '255.255.0.0', @rule.remoteIpAddressMask);
    rule.filteringFlag := NF_ALLOW;
    nf_addRule(rule, 1);

    //UDP
    FillChar(rule, sizeof(rule), 0);
    rule.ip_family := AF_INET;
    rule.protocol := IPPROTO_UDP;
    rule.direction := NF_D_OUT;
    rule.filteringFlag := NF_FILTER;
    nf_addRule(rule, 1);

    FillChar(rule, sizeof(rule), 0);
    rule.ip_family := AF_INET6;
    rule.protocol := IPPROTO_UDP;
    rule.direction := NF_D_OUT;
    rule.filteringFlag := NF_FILTER;
    nf_addRule(rule, 1);

    fActive:=True;
    Result:=True;
  end
end;

procedure StopNFDriver;
var
  I: Integer;
  MapSocket: TMapSocket;
begin
  if Not fActive then Exit;
  for I:=NFConnects.Count-1 downto 0 do
  begin
    MapSocket:=TMapSocket(NFConnects.Objects[I]);
    if Assigned(MapSocket) then MapSocket.Free;
    NFConnects.Delete(I);
  end;
  nf_free();
  nf_deleteRules();
  NFConnects.Clear;
  fTagDirs.Clear;
  fActive:=False;
end;

{ TMapSocket }

function Socket5Thread(MapSocket: TMapSocket): Integer; stdcall;
var
  Buf: Array [0..1445] of Byte;
  Len: Integer;
begin
  Result:=0;

  while Assigned(MapSocket) do
  begin
    Len:=recv(MapSocket.fClientSocket,Buf,1446,0);
    if (Len=0) or (Len=SOCKET_ERROR) then Break;
    if send(MapSocket.fSocket5,Buf,Len,0)<>Len then Break;
    inc(MapSocket.UP,Len);
    Inc(NFTotalUP,Len);
  end;

  MapSocket.fSocket5Thread:=0;
  Log('[%d][%s] MapSocket S Closed', [MapSocket.fid, MapSocket.ProcName]);
  DeleteMapSocket(MapSocket);
end;

function ClientThread(MapSocket: TMapSocket): Integer; stdcall;
var
  Buf: Array [0..1445] of Byte;
  Len: Integer;
begin
  Result:=0;

  if MapSocket.ConnectTCP=false then
  begin
    closesocket(MapSocket.fClientSocket);
    exit;
  end;

  Log('[%d][%s] SOCKS connected', [MapSocket.fid, MapSocket.ProcName]);

  MapSocket.fSocket5Thread:=BeginThread(nil,65536,@Socket5Thread,MapSocket,0,MapSocket.fSocket5ThreadID);

  while Assigned(MapSocket) do
  begin
    Len:=recv(MapSocket.fSocket5,Buf,1446,0);
    if (Len=0) or (Len=SOCKET_ERROR) then Break;
    if send(MapSocket.fClientSocket,Buf,Len,0)<>Len then Break;
    inc(MapSocket.DL,Len);
    Inc(NFTotalDL,Len);
  end;

  MapSocket.fHandleThread:=0;
  Log('[%d][%s] MapSocket C Closed', [MapSocket.fid, MapSocket.ProcName]);
  DeleteMapSocket(MapSocket);
end;

function AcceptThread(MapSocket: TMapSocket): Integer; stdcall;
var
  lasterr: DWORD;
begin
  Result:=0;
  while Assigned(MapSocket) do
  begin
    MapSocket.fClientSocket:=accept(MapSocket.fSocket,nil,nil);
    if MapSocket.fClientSocket = INVALID_SOCKET then
    begin
      lasterr:=WSAGetLastError();
      if lasterr=10004 then Exit;
      log('[%d][%s] MapSocket accept err %d',[MapSocket.fid, MapSocket.ProcName, lasterr]);
      Break;
    end;
    MapSocket.fHandleThread:=BeginThread(nil,65536,@ClientThread,MapSocket,0,MapSocket.fHandleThreadID);
    Break;
  end;
  MapSocket.fAcceptThread:=0;
end;

constructor TMapSocket.Create(Host: AnsiString; Port: AnsiString);
begin
  fAcceptThread:=0;
  fHandleThread:=0;
  fSocket5Thread:=0;
  fSocket5:=0;
  fClientSocket:=0;
  fUDPSocket:=0;
  UP:=0;
  DL:=0;
  fHost:=Host;
  fPort:=Port;
  fUDPOption:=nil;
end;

destructor TMapSocket.Destroy;
begin

  if fAcceptThread<>0 then
  begin
    Windows.TerminateThread(fAcceptThread,0);
    CloseHandle(fAcceptThread);
    fAcceptThread:=0;
  end;

  if fHandleThread<>0 then
  begin
    Windows.TerminateThread(fHandleThread,0);
    CloseHandle(fHandleThread);
    fHandleThread:=0;
  end;

  if fSocket5Thread<>0 then
  begin
    Windows.TerminateThread(fSocket5Thread,0);
    CloseHandle(fSocket5Thread);
    fSocket5Thread:=0;
  end;

  if fUDPThread<>0 then
  begin
    Windows.TerminateThread(fUDPThread,0);
    CloseHandle(fUDPThread);
    fUDPThread:=0;
  end;

  if fUDPOption<>nil then FreeMem(fUDPOption);

  if (fClientSocket<>0) then closesocket(fClientSocket);
  if (fSocket<>0) then closesocket(fSocket);
  if (fSocket5<>0) then closesocket(fSocket5);
  if (fUDPSocket<>0) then closesocket(fUDPSocket);

  inherited;
end;

function TMapSocket.HandleTCP(id: ENDPOINT_ID; info: NF_TCP_CONN_INFO): Boolean;
var
  LAddr: SOCKADDR_IN6;
  v6only: Integer;
begin
  fid:=id;
  finfo:=info;
  Result:=False;

  if ConnectS5=false then
  begin
    closesocket(fSocket5);
    exit;
  end;
  if HandshakeS5=false then
  begin
    closesocket(fSocket5);
    exit;
  end;

  fSocket:=socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);

  v6only:=0;
  if setsockopt(fSocket, IPPROTO_IPV6, IPV6_V6ONLY, PansiChar(@v6only), sizeof(v6only))=-1 then
  begin
    log('TCP setsockopt err %d',[WSAGetLastError]);
    Exit;
  end;

  FillChar(LAddr,SizeOf(SOCKADDR_IN6),0);
  LAddr.sin_family:=AF_INET6;

  if bind(fSocket,PSockAddr(@LAddr)^,SizeOf(SOCKADDR_IN6))=-1 then
  begin
    log('TCP bind err %d',[WSAGetLastError]);
    Exit;
  end;

  FillChar(LAddr,SizeOf(SOCKADDR_IN6),0);
  v6only:=SizeOf(SOCKADDR_IN6);

  getsockname(fSocket, PSockAddr(@LAddr)^, v6only);
  ListenPort:=LAddr.sin_port;

  listen(fSocket, 1024);

  fAcceptThread:=BeginThread(nil,65536,@AcceptThread,Self,0,fAcceptThreadID);

  HandleMode:='TCP';
  Result:=True;
end;

function TMapSocket.HandleUDP(id: ENDPOINT_ID; info: NF_UDP_CONN_INFO): Boolean;
begin
  fid:=id;
  finfoUDP:=info;

  HandleMode:='UDP';
  Result:=True;
end;

function TMapSocket.ConnectS5: Boolean;
var
  LastErr, I: integer;
  tcpdata: tcp_keepalive;
  ret: DWORD;
  tv: timeval;
begin
  Result:=False;

  FSocket5:=socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
  i:=0;
  if setsockopt(FSocket5, IPPROTO_IPV6, IPV6_V6ONLY, PansiChar(@i), sizeof(i))=-1 then
  begin
    log('setsockopt err %d',[WSAGetLastError]);
    Exit;
  end;

  tv.tv_sec:=4;
  tv.tv_usec:=0;
  if not WSAConnectByName(FSocket5, PAnsiChar(fHost), PAnsiChar(fPort), nil, nil, nil, nil, @tv, nil) then
  begin
    LastErr := WSAGetLastError();
    if (LastErr <> WSAEWOULDBLOCK) then
    begin
      Log('SOCKS connect error: %d', [LastErr]);
      Exit;
    end;
  end;

  tcpdata.onoff:=1;
  tcpdata.keepalivetime:=120000;
  tcpdata.keepaliveinterval:=10000;
  WSAIoctl(FSocket5, _WSAIOW(IOC_VENDOR,4), @tcpdata, sizeof(tcpdata), nil, 0, ret, nil, nil);

  Result:=True;
end;

function TMapSocket.HandshakeS5: Boolean;
var
  LastErr: integer;
  Buf: array [0 .. 255] of AnsiChar;
begin
  Result:=False;

  ZeroMemory(@Buf, SizeOf(Buf));
  Buf[0] := SOCKS5_VER;
  Buf[1] := #$01; // Number of our methods
  Buf[2] := SOCKS5_AUTH_NONE;

  send(FSocket5, Buf, 3, 0);
  LastErr := WSAGetLastError();

  if (LastErr<>0) and (LastErr <> WSAEWOULDBLOCK) then
  begin
    Log('S SendData error: %d', [LastErr]);
    exit;
  end;

  ZeroMemory(@Buf, SizeOf(Buf));

  recv(FSocket5, Buf, 3, 0);
  LastErr := WSAGetLastError();

  if (LastErr<>0) and (LastErr <> WSAEWOULDBLOCK) then
  begin
    Log('S RecvData error: %d',[LastErr]);
    exit;
  end;

  if Buf[0] <> SOCKS5_VER then
  begin
    Log('S SOCKS Ver reply %d (expected: %d)',[integer(Buf[0]), integer(SOCKS5_VER)]);
  end;

  if Buf[1] <> SOCKS5_AUTH_NONE then
  begin
    Log('S SOCKS authentication Need!', []);
    Exit;
  end;

  Result:=True;
end;

function TMapSocket.ConnectTCP: Boolean;
var
  LastErr, I: integer;
  Buf: array [0 .. 255] of AnsiChar;
  pAddr: PSockAddrIn;
  pAddr6: PSockAddrIn6;
begin
  Result:=False;

  ZeroMemory(@Buf, SizeOf(Buf));
  Buf[0] := SOCKS5_VER;
  Buf[1] := SOCKS5_REQ_CMD_CONNECT;
  Buf[2] := SOCKS5_REQ_RSV;
  I := 3;

  pAddr:=@fInfo.remoteAddress;
  pAddr6:=@fInfo.remoteAddress;

  if pAddr.sin_family=AF_INET then
  begin
    Buf[I] := SOCKS5_REQ_ATYP_IP4;
    inc(I);

    PDWORD(@Buf[I])^ := pAddr.sin_addr.S_addr;
    inc(I, SizeOf(integer));

    PWord(@Buf[I])^ := pAddr.sin_port;
    I := I + 2;
  end;

  if pAddr.sin_family=AF_INET6 then
  begin
    Buf[I] := SOCKS5_REQ_ATYP_IP6;
    inc(I);

    CopyMemory(@Buf[I],@pAddr6.sin_addr,SizeOf(in_addr6));
    inc(I, SizeOf(in_addr6));

    PWord(@Buf[I])^ := pAddr6.sin_port;
    I := I + 2;
  end;

  send(FSocket5, Buf, I, 0);

  LastErr := WSAGetLastError();
  if (LastErr <> 0) and (LastErr <> WSAEWOULDBLOCK) then
  begin
    Log('S SendData error: %d', [LastErr]);
    exit;
  end;

  ZeroMemory(@Buf, SizeOf(Buf));

  recv(FSocket5, Buf, 3, 0);

  LastErr := WSAGetLastError();
  if (LastErr <> 0) and (LastErr <> WSAEWOULDBLOCK) then
  begin
    Log('S RecvData error: %d',[LastErr]);
    exit;
  end;

  if (Buf[0] = SOCKS5_REP_VER) and (Buf[1] = SOCKS5_REP_REP_OK) then
  begin
    //Log('SOCKS attempt to (%s:%d)', [Inet_ntoa(fAddr.sin_addr), ntohs(fAddr.sin_port)]);
    result := True;
  end else begin
    Log('SOCKS connection failure: %1x', [integer(Buf[1])]);
    exit;
  end;

  SplitAddr(nil);
end;

function TMapSocket.SplitAddr(Addr: PSockAddrIn6): Boolean;
var
  ReplayAddr: TSockAddrIn;
  ReplayAddr6: sockaddr_in6;
  Buf: array [0 .. 255] of AnsiChar;
begin
  FillChar(ReplayAddr,sizeOf(TSockAddrIn),0);
  FillChar(ReplayAddr6,sizeOf(sockaddr_in6),0);

  recv(FSocket5, Buf, 1, 0);
  case ord(Buf[0]) of
    1:  //IPV4
    begin
      ReplayAddr.sin_family:=AF_INET;
      recv(FSocket5, ReplayAddr.sin_addr, 4, 0);
      recv(FSocket5, ReplayAddr.sin_port, 2, 0);
      if (Addr<>nil) then CopyMemory(Addr,@ReplayAddr,SizeOf(TSockAddrIn));
    end;
    4: //IPV6
    begin
      ReplayAddr6.sin_family:=AF_INET6;
      recv(FSocket5, ReplayAddr6.sin_addr, 16, 0);
      recv(FSocket5, ReplayAddr6.sin_port, 2, 0);
      if (Addr<>nil) then CopyMemory(Addr,@ReplayAddr6,SizeOf(sockaddr_in6));
    end;
  end;

  Result:=True;
end;

function TMapSocket.UDPAssociate: Boolean;
var
  LastErr: integer;
  Buf: array [0 .. 9] of AnsiChar;
  LAddr: SOCKADDR_IN;
begin
  Result:=False;

  if ConnectS5=false then
  begin
    closesocket(fSocket5);
    exit;
  end;
  if HandshakeS5=false then
  begin
    closesocket(fSocket5);
    exit;
  end;

  fUDPSocket:=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

  FillChar(LAddr,SizeOf(SOCKADDR_IN),0);
  LAddr.sin_family:=AF_INET;

  bind(fUDPSocket,TSockAddr(LAddr),SizeOf(SOCKADDR_IN));

  LastErr:=SizeOf(TSockAddr);
  getsockname(fUDPSocket, TSockAddr(LAddr), LastErr);

  ZeroMemory(@Buf, SizeOf(Buf));
  Buf[0] := SOCKS5_VER;
  Buf[1] := SOCKS5_REQ_CMD_UDP;
  Buf[3] := SOCKS5_REQ_ATYP_IP4;

  PDWORD(@Buf[4])^ := LAddr.sin_addr.S_addr;
  PWord(@Buf[8])^ := LAddr.sin_port;

  send(FSocket5, Buf, 10, 0);
  LastErr := WSAGetLastError();
  if (LastErr <> 0) and (LastErr <> WSAEWOULDBLOCK) then
  begin
    Log('SOCKS UDP SendData error: %d', [LastErr]);
    exit;
  end;

  ZeroMemory(@Buf, SizeOf(Buf));
  recv(FSocket5, Buf, 3, 0);
  if (Buf[0] = SOCKS5_REP_VER) and (Buf[1] = SOCKS5_REP_REP_OK) then
  begin
    //Log('UDP SOCKS5_REP_REP_OK', []);
    result := True;
  end else begin
    Log('SOCKS UDP connection failure: %1x', [integer(Buf[1])]);
    exit;
  end;

  SplitAddr(@fUDPRAddr);
end;

function UDPLoopThread(MapSocket: TMapSocket): Integer; stdcall;
var
  buf: Byte;
begin
  Result:=0;

  while Assigned(MapSocket) do
  begin
    if recv(MapSocket.fSocket5,buf,1,0)<>1 then break;
    if send(MapSocket.fSocket5,buf,1,0)<>1 then break;
  end;

  //MapSocket.fUDPThread:=0;
  //Log('[%d][%s] MapSocket UDP Closed', [MapSocket.fid, MapSocket.ProcName]);
  //DeleteMapSocket(MapSocket);
end;

function UDPThread(MapSocket: TMapSocket): Integer; stdcall;
var
  buf: Array [0..1457] of Byte;
  addr: SOCKADDR_IN6;
  len: Integer;
begin
  Result:=0;

  while Assigned(MapSocket) do
  begin
    len:=MapSocket.UDPRead(@addr,@buf,1458);
    if (len=0) or (len=-1) then Break;
    Inc(MapSocket.DL,len);
    Inc(NFTotalDL,len);
    nf_udpPostReceive(MapSocket.fid, @addr, @buf, len, MapSocket.fUDPOption);
  end;

  MapSocket.fUDPThread:=0;
  Log('[%d][%s] MapSocket UDP Closed', [MapSocket.fid, MapSocket.ProcName]);
  //DeleteMapSocket(MapSocket);
end;

function TMapSocket.UDPRead(target: PSockAddrIn6; buffer: PAnsiChar; length: Integer): Integer;
var
  size: Integer;
  retAddr: SOCKADDR_IN;
  retAddr6: SOCKADDR_IN6;
  buf: Array [0..1457] of AnsiChar;
begin
  Result:=-1;
  FillChar(Buf,1458,0);

  size:=recvfrom(fUDPSocket,buf,length,0,nil,nil);

  if size<>-1 then
  case ord(buf[3]) of
    1:
    begin
      retAddr.sin_family:=AF_INET;

      CopyMemory(@retAddr.sin_addr, @buf[4], 4);
      CopyMemory(@retAddr.sin_port, @buf[8], 2);

      CopyMemory(target, @retAddr, SizeOf(SOCKADDR_IN));

      CopyMemory(buffer, @buf[10], size-10);

      Result:=Size-10;
    end;
    4:
    begin
      retAddr6.sin_family:=AF_INET6;

      CopyMemory(@retAddr6.sin_addr, @buf[4], 16);
      CopyMemory(@retAddr6.sin_port, @buf[20], 2);

      CopyMemory(target, @retAddr6, SizeOf(SOCKADDR_IN6));

      CopyMemory(buffer, @buf[22], size-22);

      Result:=Size-22;
    end;
  end;

end;

function TMapSocket.UDPSend(target: PSockAddrIn6; buffer: PAnsiChar; length: Integer): Integer;
var
  Buf: Array [0..1457] of AnsiChar;
  slen, addrLen: Integer;
begin
  FillChar(Buf,1458,0);
  slen:=0;
  addrLen:=0;

  case target.sin_family of
    AF_INET:
    begin
      Buf[3] := SOCKS5_REQ_ATYP_IP4;

      CopyMemory(@buf[4], @PSockAddrIn(target).sin_addr, 4);
      CopyMemory(@buf[8], @PSockAddrIn(target).sin_port, 2);

      CopyMemory(@buf[10], buffer, length);

      slen:=length+10;
    end;
    AF_INET6:
    begin
      Buf[3] := SOCKS5_REQ_ATYP_IP6;

      CopyMemory(@buf[4], @target.sin_addr.addr, 16);
      CopyMemory(@buf[20], @target.sin_port, 2);

      CopyMemory(@buf[22], buffer, length);

      slen:=length+22;
    end;
  end;

  case fUDPRAddr.sin_family of
    AF_INET: addrLen:=SizeOf(SOCKADDR_IN);
    AF_INET6: addrLen:=SizeOf(SOCKADDR_IN6);
  end;

  if sendto(fUDPSocket,Buf,slen,0,PSockAddr(@fUDPRAddr),addrLen)<>slen then
    Result:=-1
  else
    Result:=length;
end;

function TMapSocket.CreateUDP(UDPOption: Pointer): Boolean;
begin
  Result:=False;
  fUDPOption:=AllocMem(PNF_UDP_OPTIONS(UDPOption).optionsLength);
  CopyMemory(fUDPOption,UDPOption,PNF_UDP_OPTIONS(UDPOption).optionsLength);

  //fUDPThread:=BeginThread(nil,65536,@UDPLoopThread,Self,0,fUDPThreadID);
  fUDPThread:=BeginThread(nil,65536,@UDPThread,Self,0,fUDPThreadID);
end;

initialization
  IsMultiThread := true;
  WSAStartup(MAKEWORD(2, 2), wd);
  NFConnects := TStringList.Create;
  fTagDirs := TStringList.Create;
  fActive:=False;
  NFTotalUP:=0;
  NFTotalDL:=0;

  NFSFILE:=nfscname+'.sys';

  mDLL:=MemoryLoadLibary(@nethelperdll);

  nf_init:=MemoryGetProcAddress(mDLL,'nf_init');
  nf_free:=MemoryGetProcAddress(mDLL,'nf_free');

  nf_registerDriver:=MemoryGetProcAddress(mDLL,'nf_registerDriver');
  nf_unRegisterDriver:=MemoryGetProcAddress(mDLL,'nf_unRegisterDriver');

  nf_tcpPostSend:=MemoryGetProcAddress(mDLL,'nf_tcpPostSend');
  nf_tcpPostReceive:=MemoryGetProcAddress(mDLL,'nf_tcpPostReceive');
  //nf_tcpClose:=MemoryGetProcAddress(mDLL,'nf_tcpClose');

  nf_udpPostSend:=MemoryGetProcAddress(mDLL,'nf_udpPostSend');
  nf_udpPostReceive:=MemoryGetProcAddress(mDLL,'nf_udpPostReceive');

  nf_addRule:=MemoryGetProcAddress(mDLL,'nf_addRule');
  nf_deleteRules:=MemoryGetProcAddress(mDLL,'nf_deleteRules');

  nf_tcpDisableFiltering:=MemoryGetProcAddress(mDLL,'nf_tcpDisableFiltering');
  //nf_udpDisableFiltering:=MemoryGetProcAddress(mDLL,'nf_udpDisableFiltering');

  nf_adjustProcessPriviledges:=MemoryGetProcAddress(mDLL,'nf_adjustProcessPriviledges');
  nf_getProcessNameW:=MemoryGetProcAddress(mDLL,'nf_getProcessNameW');
  nf_getProcessNameFromKernel:=MemoryGetProcAddress(mDLL,'nf_getProcessNameFromKernel');

finalization
  WSACleanup();

end.
