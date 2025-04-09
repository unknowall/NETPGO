unit Main;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, Vcl.Forms, Vcl.Dialogs,
  Vcl.ExtCtrls, Vcl.BaseImageCollection, Vcl.ImageCollection,
  System.ImageList, Vcl.ImgList, Vcl.VirtualImageList, Vcl.StdCtrls,
  Vcl.Controls, Vcl.WinXCtrls, Vcl.Buttons, Vcl.ComCtrls, System.Classes,
  WinSock2, ShellApi, NfUnit, SuperObject, Common, Vcl.Mask;

type
  TFrmMain = class(TForm)
    PageControl: TPageControl;
    TabSheet1: TTabSheet;
    TabSheet2: TTabSheet;
    SWRun: TToggleSwitch;
    LabP: TLabel;
    LabCT: TLabel;
    LabL: TLabel;
    RunChrome: TSpeedButton;
    VIL: TVirtualImageList;
    IC: TImageCollection;
    VIL64: TVirtualImageList;
    BtnGO: TSpeedButton;
    Timer1: TTimer;
    LabUP: TLabel;
    LabDown: TLabel;
    PageProxy: TPageControl;
    TabSheet4: TTabSheet;
    TabSheet5: TTabSheet;
    GBIplist: TGroupBox;
    LBIP: TListBox;
    GBProxy: TGroupBox;
    LBProxy: TListBox;
    LBDirs: TListBox;
    BtnDelDir: TButton;
    BtnAddDir: TButton;
    ChkProxyDir: TCheckBox;
    PageControl1: TPageControl;
    TabLink: TTabSheet;
    LVLink: TListView;
    TabSheet3: TTabSheet;
    MemLog: TMemo;
    Label1: TLabel;
    TabSheet6: TTabSheet;
    LbItems: TListBox;
    edCMD: TLabeledEdit;
    edParam: TLabeledEdit;
    edPort: TLabeledEdit;
    edCfg: TLabeledEdit;
    edPath: TLabeledEdit;
    LBUpd: TListBox;
    Label2: TLabel;
    EdUpd: TEdit;
    BtnSave: TButton;
    DelUpd: TButton;
    AddUpd: TButton;
    BtnEdit: TButton;
    TabSheet7: TTabSheet;
    Label3: TLabel;
    Label4: TLabel;
    LinkLabel1: TLinkLabel;
    Label5: TLabel;
    ListBox1: TListBox;
    procedure FormCreate(Sender: TObject);
    procedure FormClose(Sender: TObject; var Action: TCloseAction);
    procedure BtnGOClick(Sender: TObject);
    procedure LBProxyClick(Sender: TObject);
    procedure RunChromeClick(Sender: TObject);
    procedure SWRunMouseUp(Sender: TObject; Button: TMouseButton; Shift: TShiftState; X, Y: Integer);
    procedure PageControlChange(Sender: TObject);
    procedure Timer1Timer(Sender: TObject);
    procedure BtnAddDirClick(Sender: TObject);
    procedure BtnDelDirClick(Sender: TObject);
    procedure SaveDirs;
    procedure LVLinkData(Sender: TObject; Item: TListItem);
    procedure TabSheet6Show(Sender: TObject);
    procedure LbItemsClick(Sender: TObject);
    procedure LBUpdClick(Sender: TObject);
    procedure AddUpdClick(Sender: TObject);
    procedure DelUpdClick(Sender: TObject);
    procedure BtnEditClick(Sender: TObject);
    procedure BtnSaveClick(Sender: TObject);
  private
  public
    procedure WMThread_msg(var  Msg: TMessage);  message  WM_THREAD_MSG;
  end;

var
  FrmMain: TFrmMain;

implementation

{$R *.dfm}

procedure AddLog(S: String);
begin
  if Not Assigned(FrmMain.MemLog) then Exit;
  if FrmMain.MemLog.Lines.Count>1000 then FrmMain.MemLog.Lines.Clear;
  FrmMain.MemLog.Lines.Add(FormatDateTime('hh:mm:ss',Now())+' '+S);
end;

procedure TFrmMain.FormClose(Sender: TObject; var Action: TCloseAction);
begin
  TerminateProcess(ProcessInfo.hProcess,0);
  Proxy:=nil;
  cfg:=nil;
end;

procedure TFrmMain.FormCreate(Sender: TObject);
var
  I,IPS: Integer;
  regKey: HKEY;
  Val: PChar;
  JSONStr: String;
begin
  MyPath:=ExtractFilePath(ParamStr(0));
  FrmHeight:=420;
  FrmMain.Caption:=ConstTitle;
  ReadOutPipe:=0;
  //GetDebugPrivs;
  CB:=nil;


  if (ParamStr(1)='-u') or (ParamStr(1)='u') then
  begin
    UnNFDriver;
    Application.Terminate;
  end;

  JSONStr:=LoadString(MyPath+'NETPGO.cfg');
  if JSONStr='' then Exit;
  JSONStr := JSONStr.Replace(#$d#$A,'');
  Cfg:=SO(JSONStr);
  Proxys:=Cfg.A['proxys'];
  ChromeUserPath:=Cfg.S['userdatapath'];

  ChromePath:='';
  if RegOpenKeyEX(HKEY_LOCAL_MACHINE,
    'Software\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe',
    0,
    KEY_READ,
    regKey) = 0 then
  begin
    Val:=AllocMem(1024);
    RegQueryValue(regKey,'',Val,I);
    RegCloseKey(regKey);
    ChromePath:=Val;
    FreeMem(Val);
    RunChrome.Visible:=True;
  end;

  IPS:=0;
  for I := 0 to Proxys.Length -1 do
  begin
    LBProxy.AddItem(Proxys.O[I].S['name'],nil);
    IPS:=IPS+Proxys.O[I].A['ip'].Length;
  end;
  LBProxy.ItemIndex:=0;
  LBProxyClick(nil);
  AddLog(Format('加载 %d 个代理, %d 个订阅地址',[Proxys.Length,IPS]));

  Proxydirs:=Cfg.A['proxydirs'];
  for I:=0 to ProxyDirs.Length-1 do
  begin
    LbDirs.Items.Add(Proxydirs.S[I]);
  end;

  Pagecontrol.ActivePageIndex:=0;
  PageControlChange(self);

  //AllocConsole();
  //AttachConsole(ATTACH_PARENT_PROCESS);
end;

procedure TFrmMain.SaveDirs;
var
  I: Integer;
begin
  Proxydirs.Clear(true);
  for I:=0 to LbDirs.Count-1 do
  begin
    Proxydirs.Add(LbDirs.Items[I]);
  end;
  Cfg.SaveTo(MyPath+'NETPGO.cfg');
end;

procedure TFrmMain.LBProxyClick(Sender: TObject);
var
  I,Idx: Integer;
begin
  if LBProxy.ItemIndex<0 then Exit;
  Idx:=LBProxy.ItemIndex;
  Proxy:=Proxys.O[Idx];
  LBIP.Clear;
  LBIP.AddItem('不更新订阅',nil);
  for I:=0 to Proxy.A['ip'].Length -1 do
  begin
    //LBIP.AddItem(ExtractURLSite(Proxy.A['ip'].S[I]),nil);
    LBIP.AddItem('服务订阅地址 - '+IntToStr(I+1),nil);
  end;
  LBIP.ItemIndex:=0;
  LabP.Caption:=Proxy.S['name'];
end;

procedure TFrmMain.LVLinkData(Sender: TObject; Item: TListItem);
var
  MapS: TMapSocket;
  pAddr: PSockAddrIn;
begin
  try

  if (Item.Index<0) or (Item.Index>NFConnects.Count) then Exit;
  MapS:=TMapSocket(NFConnects.Objects[Item.Index]);
  if Not Assigned(Maps) then Exit;

  Item.Caption:=MapS.PID;

  Item.SubItems.Add(ExtractFileName(MapS.ProcName));
  Item.SubItems.Add(InetStr(Maps.fInfo.ip_family));

  pAddr:=@Maps.fInfo.localAddress;
  Item.SubItems.Add(IntToStr(ntohs(pAddr.sin_port)));

  Item.SubItems.Add(BytesToStr(Maps.UP));
  Item.SubItems.Add(BytesToStr(Maps.DL));

  pAddr:=@Maps.fInfo.remoteAddress;
  Item.SubItems.Add(String(ConvertIP(PSOCKADDR(pAddr))));

  Item.SubItems.Add(IntToStr(ntohs(pAddr.sin_port)));

  except
  end;

end;

procedure TFrmMain.PageControlChange(Sender: TObject);
begin
  if PageControl.ActivePageIndex>=1 then
  begin
    FrmMain.Height:=420;
    FrmMain.Width:=765;
    LVLink.Items.Count:=NFConnects.Count;
  end else begin
    FrmMain.Height:=420;
    FrmMain.Width:=380;
    if State=2 then FrmMain.Height:=PageProxy.Top+MINUI_HEIGHT;
  end;
end;

procedure TFrmMain.RunChromeClick(Sender: TObject);
begin
  if State=2 then
  ShellExecuteW(0,'open','chrome.exe',
    PChar(' --user-data-dir='+ChromeUserPath+' --proxy-server="'+PortStr+'"'),
    PChar(MyPath),
    SW_SHOW
  )
  else BtnGOClick(nil);
end;

procedure TFrmMain.SWRunMouseUp(Sender: TObject; Button: TMouseButton; Shift: TShiftState; X, Y: Integer);
begin
  BtnGOClick(nil);
end;

procedure TFrmMain.BtnAddDirClick(Sender: TObject);
var
  Dirstr: String;
begin
  DirStr:=SelectDirectory('选择需代理程序所在目录');
  if (DirStr<>'') and (LbDirs.Items.IndexOf(DirStr)=-1) then
  begin
    LbDirs.AddItem(DirStr,nil);
  end;
  SaveDirs;
end;

procedure TFrmMain.BtnDelDirClick(Sender: TObject);
var
  I: Integer;
begin
  for I:=LbDirs.Items.Count-1 downto 0 do
  begin
    if LBDirs.Selected[I] then LBDirs.Items.Delete(I);
  end;
  SaveDirs;
end;

procedure TFrmMain.BtnGOClick(Sender: TObject);
var
  dwID: DWORD;
  sPort: String;
begin
  if (LBIP.ItemIndex<0) or (Proxy=nil) then exit;
  PathStr:=Proxy.S['path'];
  BinFile:=Proxy.S['bin'];
  BinCmd:=' '+Proxy.S['cmd'];
  PortStr:=Proxy.S['port'];
  ShowUI:=Not Proxy.B['showui'];
  DecodeCfg:=Proxy.B['decfg'];
  CfgFile:=PathStr+'\'+Proxy.S['cfg'];
  if LBIP.ItemIndex>0 then  UpdIpAddr:=Proxy.A['ip'].S[LBIP.ItemIndex-1];
  BinPath:=MyPath+PathStr+'\'+BinFile;
  UrlFileName:=ExtractUrlFileName(UpdIpAddr);
  if (LBIP.ItemIndex=0) and (State=0) then State:=1;
  case State of
    0:
    begin
      if CB<>nil then Exit;
      FrmMain.Caption:=ConstTitle+'IP更新中......';
      CreateThread(nil,0,@DownToFile,Pointer(FrmMain.Handle),0,dwID);
    end;
    1:
    begin
      if FileExists(BinPath) then
      begin
        RunProcess(BinPath+BinCmd,MyPath+PathStr+'\', FrmMain.Handle);
        if Not ChkProxyDir.Checked then
        begin
          sPort:=PortStr;
          repeat
            sPort:=Copy(sPort,Pos(':',sPort)+1,Length(sPort)-Pos(':',sPort));
          until Pos(':',sPort)=0;
          SetNfDriver('127.0.0.1', AnsiString(sPort));
          AddPTargets(LBDirs.Items);
        end;
      end;
    end;
    2:
    begin
      TerminateProcess(ProcessInfo.hProcess,0);
      StopNfDriver;
    end;
  end;
end;

procedure TFrmMain.Timer1Timer(Sender: TObject);
var
  Tr,Trd: Int64;
begin
  if State<>2 then Exit;
  Timer1.Enabled:=False;

  Tr:=NFTotalUP;
  Trd:=NFTotalDL;

  //FrmMain.Caption:=ConstTitle+'  -  up '+BytesToStr(Tr-OTrU)+'/s, down '+BytesToStr(Trd-OtrD)+'/s';
  LabCT.Caption:='流量 '+BytesToStr(Tr+Trd);
  LabUP.Caption:='上传 '+BytesToStr(Tr-OTrU)+'/S';
  LabDown.Caption:='下载 '+BytesToStr(Trd-OtrD)+'/S';
  LabL.Caption:='连接 '+IntToStr(NFConnects.Count);

  OTrU:=Tr;
  OtrD:=Trd;

  if PageControl.ActivePageIndex=1 then
    LVLink.Items.Count:=NFConnects.Count;

  Timer1.Enabled:=True;
end;

procedure TFrmMain.WMThread_msg(var Msg: TMessage);
var
  Buff: PAnsiChar;
begin
  case Msg.LParam of
    0:
    begin
      if FileExists(MyPath+UrlFileName) then
      begin
        if FileExists(MyPath+CfgFile) then
          CopyFile(PWChar(MyPath+CfgFile),PWChar(MyPath+CfgFile+'_BACKUP'),False);
        if DecodeCfg then DecodeBase64File(MyPath+UrlFileName);
        CopyFile(PWChar(MyPath+UrlFileName),PWChar(MyPath+CfgFile),False);
        DeleteFile(PWChar(MyPath+UrlFileName));
      end;
      AddLog('更新成功 - '+CfgFile);
      State:=1;
      FrmMain.Caption:=ConstTitle;
      BtnGoClick(nil);
    end;
    1:
    begin
      FrmMain.Caption:=ConstTitle+'IP更新失败';
      AddLog('更新失败: '+IntToStr(GetLastError));
    end;
    2:
    begin
      SWRun.State:=tssON;
      BtnGo.ImageIndex:=3;
      FrmMain.Height:=PageProxy.Top+MINUI_HEIGHT;
      //RunChromeClick(nil);
    end;
    3:
    begin
      case Msg.WParam of
        0:
        begin
          //PipeStart
          GBProxy.Enabled:=False;
          GBIplist.Enabled:=False;
          LBProxy.Enabled:=False;
          LBIP.Enabled:=False;
        end;
        1:
        begin
          //PipeStop
          State:=0;
          AddLog('代理进程关闭！');
          SWRun.State:=tssOFF;
          BtnGo.ImageIndex:=4;
          FrmMain.Height:=FrmHeight;
          GBProxy.Enabled:=True;
          GBIplist.Enabled:=True;
          LBProxy.Enabled:=True;
          LBIP.Enabled:=True;
          //FrmMain.Caption:=ConstTitle;
        end;
      end;
    end;
    4:
    begin
      Buff:=PAnsiChar(Msg.WParam);
      AddLog(String(Buff));
      FreeMem(Buff);
    end;
  end;
end;

//Setting

procedure TFrmMain.TabSheet6Show(Sender: TObject);
begin
  LbItems.Clear;
  for var I:=0 to Proxys.Length-1 do
  begin
    LbItems.Items.Add(Proxys.O[I].S['name']);
  end;
  LbItems.ItemIndex:=0;
  LbItemsClick(nil);
end;

procedure TFrmMain.LbItemsClick(Sender: TObject);
var
  idx: Integer;
begin
  idx := LbItems.ItemIndex;
  if idx = -1 then Exit;

  edCmd.Text := Proxys.O[idx].S['bin'];
  edCfg.Text := Proxys.O[idx].S['cfg'];
  edPath.Text := Proxys.O[idx].S['path'];
  edParam.Text := Proxys.O[idx].S['cmd'];
  edPort.Text := Proxys.O[idx].S['port'];

  Lbupd.Items.Clear;
  for var I := 0 to Proxys.O[idx].A['ip'].Length-1 do
  begin
    Lbupd.Items.Add(Proxys.O[idx].A['ip'].S[I]);
  end;
end;

procedure TFrmMain.LBUpdClick(Sender: TObject);
var
  idx: Integer;
begin
  idx := LbUpd.ItemIndex;
  if idx = -1 then Exit;

  Edupd.Text:=LbUpd.Items[idx];
end;

procedure TFrmMain.DelUpdClick(Sender: TObject);
var
  idx: Integer;
begin
  idx := LbUpd.ItemIndex;
  if idx = -1 then Exit;

  LbUpd.Items.Delete(idx);
  Edupd.Text:='';
end;

procedure TFrmMain.AddUpdClick(Sender: TObject);
begin
  LbUpd.Items.Add('http://127.0.0.1/newconfig.txt');
  LbUpd.ItemIndex := LbUpd.Items.Count-1;
  Edupd.Text:='http://127.0.0.1/newconfig.txt';
end;

procedure TFrmMain.BtnEditClick(Sender: TObject);
var
  idx: Integer;
begin
  idx := LbUpd.ItemIndex;
  if idx = -1 then Exit;

  LbUpd.Items[idx]:=Edupd.Text;
end;

procedure TFrmMain.BtnSaveClick(Sender: TObject);
var
  idx: Integer;
begin
  idx := LbItems.ItemIndex;
  if idx = -1 then Exit;

  Proxys.O[idx].S['bin'] := edCmd.Text;
  Proxys.O[idx].S['cfg'] := edCfg.Text;
  Proxys.O[idx].S['path'] := edPath.Text;
  Proxys.O[idx].S['cmd'] := edParam.Text;
  Proxys.O[idx].S['port'] := edPort.Text;

  Proxys.O[idx].A['ip'].Clear(true);
  for var I := 0 to LbUpd.Items.Count-1 do
  begin
    Proxys.O[idx].A['ip'].Add(LbUpd.Items[i]);
  end;

  Cfg.SaveTo(MyPath+'NETPGO.cfg');
end;

end.
