program NETPGO;

uses
  Vcl.Forms,
  Main in 'Main.pas' {FrmMain},
  Vcl.Themes,
  Vcl.Styles;

{$R *.res}

begin
  Application.Initialize;
  Application.MainFormOnTaskbar := True;
  TStyleManager.TrySetStyle('Onyx Blue');
  Application.CreateForm(TFrmMain, FrmMain);
  Application.Run;
end.
