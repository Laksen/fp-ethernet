program test;

uses
  sysutils,
  fpethbuf, fpethcfg, fpethip, fpethudp, fpethtcp, fpetharp, fpethtypes, linuxraw, fpethif, fpethicmp;

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
  _if.IPv4:=IPv4Address(192,168,87,104);
  _if.Output:=@send;

  _if.MTU_Eth:=1400;

  _if.IPTTL:=64;

  AddIF(@_if);

  Start;

  {write(ARPLookupIPv4(IPv4Address(192,168,87,102), addr), ' + ');
  writeln(getstr(addr));
  t:=GetTickCount; }

  repeat
    x:=Recv;
    if assigned(x) then
      begin
        //writeln('Got frame: ', x^.TotalSize);

        {x^.Read(dst, sizeof(dst), 0);
        x^.Read(src, sizeof(src), 6);
        x^.Read(typ, sizeof(typ), 12);

        writeln(x^.TotalSize:5, ' - [',GetStr(src),']=>[',GetStr(dst),'] = ', hexStr(typ,4));}

        EthInput(_if, x);

        {if (GetTickCount-t)>100 then
          begin
            write(ARPLookupIPv4(IPv4Address(192,168,87,102), addr), ' + ');
            writeln(getstr(addr));
            t:=GetTickCount;
          end;}

        DoTick();

        //x^.DecRef;
      end;
  until false;

  Stop;

  {x:=AllocateBuffer(6);

  x^.Flags:=[bfWritten];

  x:=x^.Expand(6,8);

  y:='abcdefgljhafkjsah';
  z:='                 ';

  writeln('Wrote: ', x^.Write(y[1], length(y), 2));
  writeln('Read: ', x^.Read(z[1], length(z), 2));

  writeln('"'+y+'"');
  writeln('"'+z+'"');}

  {while assigned(x) do
    begin
      writeln(x^.TotalSize);
      x:=x^.Expand(2,0);
    end;}
end.

