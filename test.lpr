program test;

uses
  fpethbuf, fpethcfg, fpethip, fpethudp, fpethtcp, fpetharp, fpethtypes, linuxraw, fpethif, fpethicmp, fpethdhcp;

var
  x: PBuffer;
  src,dst: THWAddress;
  typ: word;
  _if: TNetif;
  addr: THWAddress;
  t: LongWord = 0;
  ts: TSocketHandle;
  oldDesc: LongInt = 0;

  total: longword;

procedure DoRecv(ASock: TSocketHandle; AData: pointer);
  var
    buf: string;
    data: SizeInt;
  begin
    data:=TCPGetDataAvailable(ASock);

    if data>0 then
      begin
        //setlength(buf,data);
        //TCPGetData(ASock)^.Read(buf[1], data, 0);
        TCPRead(ASock, data);

        inc(total,data);
        write(#13,'Data: ', total:10);
        //write(buf);
      end;

    //writeln('Recv: Available data = ', data);
  end;

begin
  _if.HWAddr:=HWAddress($38,$2c,$4a,$74,$09,$a0);
  _if.IPv4:=IPv4Address(192,168,87,103);
  _if.SubMaskv4:=IPv4Address(255,255,255,0);

  _if.HWAddr:=HWAddress($38,$2c,$4a,$74,$09,$a1);
  _if.IPv4:=IPv4Address(0,0,0,0);
  _if.Output:=@send;

  _if.MTU_Eth:=1400;
  _if.Flags:=[ifNoPadding];

  _if.IPTTL:=64;

  AddIF(@_if);

  DHCPStartClient(_if);

  ts:=TCPCreateSocket();
  TCPBind(ts, IPAddress(IPv4_AnyAddr), 23);
  TCPListen(ts);

  TCPRecvCallback(ts, @DoRecv);

  Start;

  repeat
    x:=Recv;
    if assigned(x) then
      EthInput(_if, x);

    if DescCount<>oldDesc then
      writeln('[',DescCount,']');
    oldDesc:=DescCount;
    
    DoTick();
  until false;

  Stop;
end.

