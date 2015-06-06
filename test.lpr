program test;

uses
  sysutils,

{$ifdef UNIX}
  linuxraw,
{$endif UNIX}
  fpethbuf, fpethcfg, fpethip, fpethudp, fpethtcp, fpetharp, fpethtypes, fpethif, fpethicmp, fpethdhcp;

var
  x: PBuffer;
  src,dst: THWAddress;
  typ: word;
  _if: TNetif;
  addr: THWAddress;
  t: LongWord = 0;

begin
  _if.HWAddr:=HWAddress($38,$2c,$4a,$74,$09,$a0);
  _if.IPv4:=IPv4Address(192,168,87,103);
  _if.SubMaskv4:=IPv4Address(255,255,255,0);

  _if.HWAddr:=HWAddress($38,$2c,$4a,$74,$09,$a1);
  _if.IPv4:=IPv4Address(0,0,0,0);
  _if.Output:=@send;

  _if.MTU_Eth:=1400;

  _if.IPTTL:=64;

  AddIF(@_if);

  DHCPStartClient(_if);

  Start;

  repeat
    x:=Recv;
    if assigned(x) then
      EthInput(_if, x);
    
    DoTick();
  until false;

  Stop;
end.

