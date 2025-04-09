unit Common;

interface

uses
  Windows, Messages, SysUtils, Classes, WinSock2, AnsiStrings,
  ActiveX, UrlMon, ShellApi, ShlObj, SuperObject, System.NetEncoding;

const
  WM_THREAD_MSG   =  WM_USER  +  $FF;
  ConstTitle = 'NETPGO Ver 0.2.2 ';
  MINUI_HEIGHT = 40;

type
  TUrlCallback=class(TInterfacedObject, IBindStatusCallback, IHttpSecurity)
  public
    function OnStartBinding(dwReserved: DWORD; pib: IBinding): HResult; stdcall;
    function GetPriority(out nPriority): HResult; stdcall;
    function OnLowResource(reserved: DWORD): HResult; stdcall;
    function OnProgress(ulProgress, ulProgressMax, ulStatusCode: ULONG; szStatusText: LPCWSTR): HResult; stdcall;
    function OnStopBinding(hresult: HResult; szError: LPCWSTR): HResult; stdcall;
    function GetBindInfo(out grfBINDF: DWORD; var bindinfo: TBindInfo): HResult; stdcall;
    function OnDataAvailable(grfBSCF: DWORD; dwSize: DWORD; formatetc: PFormatEtc; stgmed: PStgMedium): HResult; stdcall;
    function OnObjectAvailable(const iid: TGUID; punk: IUnknown): HResult; stdcall;
    function OnSecurityProblem(dwProblem: DWORD): HResult; stdcall;
    function GetWindow(const guidReason: TGUID; out hwnd): HResult; stdcall;
  end;

  function BytesToStr(Value: Int64): String;
  function InetStr(f: Word): String;
  function LoadString(AFile: String): String;
  function DecodeBase64File(AFile: String): Boolean;
  function Is64Bit(AExe: String): Boolean;
  function ExtractUrlFileName(const AUrl: string): string;
  function SelectDirectory(sCaption:string):string;

  function RunProcess(S: String; CurrPath: String; Hwnd: THandle): Boolean;
  function DownToFile(Hwnd: Thandle): DWORD; stdcall;

var
  MyPath: String;
  Cfg,Proxy: ISuperObject;
  Proxys, Proxydirs: TSuperArray;

  ReadOutPipe,WriteOutPipe: THandle;
  ProcessInfo: TProcessInformation;

  ChromePath, ChromeUserPath, UrlFileName, UpdIpAddr,
  BinPath,BinCmd,PathStr,BinFile,CfgFile,PortStr: String;
  ShowUI, DecodeCfg: Boolean;
  FrmHeight, State: Integer;
  OTrU,OTrD: Int64;

  CB: TUrlCallback;

implementation

function BytesToStr(Value: Int64): String;
const
  KBYTES = Int64(1024);
  MBYTES = KBYTES * 1024;
  GBYTES = MBYTES * 1024;
  TBYTES = GBYTES * 1024;
begin
  if (Value = 0) then
    Result := '0B'
  else if (Value < KBYTES) then
    Result := Format('%dB', [Value])
  else if (Value < MBYTES) then
    Result := FormatFloat('0.##KB', Value / KBYTES)
  else if (Value < GBYTES) then
    Result := FormatFloat('0.##MB', Value / MBYTES)
  else if (Value < TBYTES) then
    Result := FormatFloat('0.##GB', Value / GBYTES)
  else
    Result := FormatFloat('0.##TB', Value / TBYTES);
end;

function InetStr(f: Word): String;
begin
  case f of
    AF_INET: Result:='IPv4';
    AF_INET6: Result:='IPv6';
  end;
end;

function LoadString(AFile: String): String;
var
  FS: TBytesStream;
begin
  FS:=TBytesStream.Create();
  try
    FS.LoadFromFile(AFile);
    Result:=TEncoding.UTF8.GetString(FS.Bytes);
  except
    Result:='';
  end;
  FS.Free;
end;

function DecodeBase64File(AFile: String): Boolean;
var
  FS: TBytesStream;
  Val: String;
  SS: TStringStream;
begin
  Result:=True;
  FS:=TBytesStream.Create();
  try
    FS.LoadFromFile(AFile);
    Val:=TEncoding.UTF8.GetString(TNetEncoding.Base64.Decode(FS.Bytes));
    SS:=TStringStream.Create;
    SS.WriteString(Val);
    SS.SaveToFile(AFile);
    SS.Free;
  except
    Result:=False;
  end;
  FS.Free;
end;

function Is64Bit(AExe: String): Boolean;
var
  HF: HFILE;
  Buf: Pointer;
  Len: DWORD;
  ImageNtHeaders: PImageNtHeaders;
begin
  Result:=False;
  Buf:=AllocMem(1024);
  try
    HF:= CreateFile(PChar(AExe),GENERIC_READ,0,nil,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0);
    ReadFile(HF,Buf^,1024,Len,nil);
    CloseHandle(HF);
    ImageNtHeaders:=PImageNtHeaders(Int64(Buf) + PImageDosHeader(Buf)._lfanew);
    case ImageNtHeaders.FileHeader.Machine of
      IMAGE_FILE_MACHINE_I386: Result:=False;
      IMAGE_FILE_MACHINE_AMD64: Result:=True;
    end;
  except
  end;
  FreeMem(Buf);
end;

function ExtractUrlFileName(const AUrl: string): string;
var
  I: Integer;
begin
  I := LastDelimiter('\:/', AUrl);
  Result := Copy(AUrl, I + 1, MaxInt);
end;

function SelectDirectory(sCaption:string):string;
var
  bi: TBrowseInfo;
begin
  if sCaption='' then sCaption:='选择目录';
  ZeroMemory(@bi,SizeOf(bi));
//  if DirectoryExists(sRootDir) then
//    SHILCreateFromPath(PChar(sRootDir),bi.pidlRoot,R)
//  else
    SHGetSpecialFolderLocation(0,CSIDL_DRIVES,bi.pidlRoot);
  bi.hwndOwner:=0;
  bi.lpszTitle:=PChar(sCaption);
  SetLength(Result,MAX_PATH+1);
  if not SHGetPathFromIDList(SHBrowseForFolder(bi),PChar(Result)) then
    SetLength(Result,0);
end;

procedure GetDebugPrivs;
var
  hToken: THandle;
  tkp: TTokenPrivileges;
  retval: dword;
Const
  SE_DEBUG_NAME = 'SeDebugPrivilege' ;
begin
  if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES or  TOKEN_QUERY, hToken)) then
  begin
    LookupPrivilegeValue(nil, SE_DEBUG_NAME  , tkp.Privileges[0].Luid);
    tkp.PrivilegeCount := 1;
    tkp.Privileges[0].Attributes := SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(hToken, false, tkp, 0, nil, retval);
  end;
end;

procedure InjectDll(hProcess: THandle;  DLL: AnsiString);
var
  hThread, TID: Cardinal;
  Parameters: pointer;
  BytesWritten: SIZE_T;
  pThreadStartRoutine: FARPROC;
begin
  Parameters := VirtualAllocEx(hProcess, nil, Length(DLL)+1, MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE);
  WriteProcessMemory(hProcess,Parameters,Pointer(DLL),Length(DLL)+1,BytesWritten);
  pThreadStartRoutine := GetProcAddress(GetModuleHandle('KERNEL32.DLL'), 'LoadLibraryA');
  hThread := CreateRemoteThread(hProcess, nil, 0, pThreadStartRoutine, Parameters, 0, TID);
  WaitForSingleObject(hThread, INFINITE);
  CloseHandle(hThread);
  VirtualFreeEx(hProcess, Parameters, 0, MEM_RELEASE);
end;

procedure InjectDllBy(PID: DWORD);
var
  hProcess: Cardinal;
  bIs64: BOOL;
  InjecterStr,InjectDllStr: String;
begin
  if PID=0 then Exit;
  hProcess:=OpenProcess(PROCESS_QUERY_INFORMATION,False,PID);

  IsWow64Process(hProcess,bIs64);
  if Not bIs64 then
  begin
    InjecterStr:=MyPath+'Injector64.exe';
    InjectDllStr:='0 '+IntToStr(PID)+' '+MyPath+'GO64.dll';
  end else begin
    InjecterStr:=MyPath+'Injector32.exe';
    InjectDllStr:='0 '+IntToStr(PID)+' '+MyPath+'GO32.dll';
  end;

  CloseHandle(hProcess);

  ShellExecute(0,'open',PChar(InjecterStr),PChar(InjectDllStr),PChar(MyPath),SW_HIDE);
end;

function ReadPipeThread(hWND: THandle): DWORD; stdcall;
var
  wrResult, BytesRead, Avail: DWORD;
  Dest: Array [0..1023] of AnsiChar;
  TmpStr: String;
  SendStr: PAnsiChar;
  SendS: AnsiString;
  I,P: Integer;
begin
  Result := 0;
  PostMessage(hWND,WM_THREAD_MSG,0,3);
  while Result = 0 do
  begin
    wrResult := WaitForSingleObject(ProcessInfo.hProcess, 500);
    if PeekNamedPipe(ReadOutPipe, @Dest[0], 1024, @Avail, nil, nil) then
    begin
      if Avail > 0 then
      begin
        try
          FillChar(Dest, SizeOf(Dest), 0);
          ReadFile(ReadOutPipe, Dest[0], Avail, BytesRead, nil);
          for i := 0 to Length(Dest) - 1 do
            if Dest[i] = #13 then Dest[i] := ' ';
          TmpStr := TmpStr + String(Dest);
          p := Pos(#10, TmpStr); // \n 断行
          while p > 0 do
          begin
            SendS:=AnsiString(Copy(TmpStr, 1, p - 1));
            //AddLog(Copy(TmpStr, 1, p - 1));
            SendStr:=AllocMem(1024);
            AnsiStrings.StrCopy(SendStr, PAnsiChar(SendS));
            PostMessage(hWND, WM_THREAD_MSG, WPARAM(@SendStr[0]), 4);
            // \n 前面的加入一行，后面的留到下次
            TmpStr := Copy(TmpStr, p + 1, Length(TmpStr) - p);
            p := Pos(#10, TmpStr);
          end;
        except
        end;
      end;
      if State=1 then
      begin
        State:=2;
        PostMessage(hWND,WM_THREAD_MSG,0,2);
      end;
    end;
    if wrResult <> WAIT_TIMEOUT then Result := 1;
  end;
  PostMessage(hWND,WM_THREAD_MSG,1,3);
end;

function DownToFile(Hwnd: Thandle): DWORD; stdcall;
var
  Ret: HRESULT;
begin
  Result:=0;
  CB:=TUrlCallback.Create;
  try
    Ret:=UrlDownloadToFile(nil,PChar(UpdIpAddr),PChar(MyPath+UrlFileName),0,CB as IBindStatusCallback);
    if Ret=S_OK then
      PostMessage(Hwnd,WM_THREAD_MSG,0,0)
    else
      PostMessage(Hwnd,WM_THREAD_MSG,0,1);
  except
  end;
  CB:=nil;
end;

function RunProcess(S: String; CurrPath: String; Hwnd: THandle): Boolean;
var
//  ExeName: PChar;
  StartupInfo: TStartupInfo;
  Security: TSecurityAttributes;
  dwID: DWORD;
begin
  Result:=False;
  FillChar(ProcessInfo,sizeof(TProcessInformation),0);
  FillChar(StartupInfo,Sizeof(TStartupInfo),0);
  FillChar(Security,Sizeof(TSecurityAttributes),0);
  StartupInfo.cb := SizeOf(TStartupInfo);
  Security.nlength := SizeOf(TSecurityAttributes);
  Security.binherithandle := true;
  Security.lpsecuritydescriptor := nil;
  if Hwnd<>0 then
  begin
    Createpipe(ReadOutPipe, WriteOutPipe, @Security, 0);
    StartupInfo.hStdOutput := WriteOutPipe;
    //StartupInfo.hStdInput := ReadIn;
    StartupInfo.hStdError := WriteOutPipe;
    StartupInfo.dwFlags := STARTF_USESTDHANDLES + STARTF_USESHOWWINDOW;
    StartupInfo.wShowWindow := SW_HIDE;
  end else begin
    StartupInfo.dwFlags := STARTF_USESHOWWINDOW;
    StartupInfo.wShowWindow := SW_SHOW;
  end;
  If CreateProcess(nil,PChar(S),@Security,@Security,True,CREATE_SUSPENDED,nil,PChar(CurrPath),StartupInfo,ProcessInfo) then
  begin
    //InjectDll(Processinfo.hProcess, MyPath+'GO32.dll');
    Result:=True;
    if Hwnd<>0 then CreateThread(nil,0,@ReadPipeThread, Pointer(Hwnd), 0,dwID);
    ResumeThread(ProcessInfo.hThread);
    //InjectDllBy(Processinfo.dwProcessId);
  end;
end;

{ TUrlCallback }

function TUrlCallback.GetBindInfo(out grfBINDF: DWORD; var bindinfo: TBindInfo): HResult;
begin
  Result:=S_OK;
end;

function TUrlCallback.GetPriority(out nPriority): HResult;
begin
  Result:=S_OK;
end;

function TUrlCallback.GetWindow(const guidReason: TGUID; out hwnd): HResult;
begin
  Result:=S_OK;
end;

function TUrlCallback.OnDataAvailable(grfBSCF, dwSize: DWORD; formatetc: PFormatEtc; stgmed: PStgMedium): HResult;
begin
  Result:=S_OK;
end;

function TUrlCallback.OnLowResource(reserved: DWORD): HResult;
begin
  Result:=S_OK;
end;

function TUrlCallback.OnObjectAvailable(const iid: TGUID; punk: IInterface): HResult;
begin
  Result:=S_OK;
end;

function TUrlCallback.OnProgress(ulProgress, ulProgressMax, ulStatusCode: ULONG; szStatusText: LPCWSTR): HResult;
begin
  //FrmMain.Caption:=ConstTitle+' '+IntToStr(ulProgress)+'\'+IntToStr(ulProgressMax);
  Result:=S_OK;
end;

function TUrlCallback.OnSecurityProblem(dwProblem: DWORD): HResult;
begin
  Result:=S_OK;
end;

function TUrlCallback.OnStartBinding(dwReserved: DWORD; pib: IBinding): HResult;
begin
  Result:=S_OK;
end;

function TUrlCallback.OnStopBinding(hresult: HResult; szError: LPCWSTR): HResult;
begin
  Result:=S_OK;
end;

end.
