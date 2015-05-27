unit fpethdhcp;

interface

uses
  fpethif, fpethudp,
  fpethbuf, fpethtypes,
  fpethcfg;

function DHCPStartClient(var AIF: TNetif): boolean;

procedure DHCPTick(ADeltaMS: SmallInt);

implementation

type
  TDHCPState = (dsNotUsed, dsInit, dsSelecting, dsRequesting, dsBound, dsRenewing, dsRebinding);

  TDHCPClient = record
    State: TDHCPState;
    T1, T2: longint;
    XID: longword;
    _IF: PNetif;
  end;

const
  DHCP_Port = 67;

  BOOT_REQUEST = 1;
  BOOT_REPLY = 2;

  HT_ETHERNET = 1;

  DHCP_COOKIE = $63825363;

var
  Clients: array[0..DHCPClientCount-1] of TDHCPClient;
  XIDCounter: longword = 0;
  sock: TUDPSocketHandle = nil;

{$packrecords 1}

type
  TDHCPHeader = record
    OP,
    HTYPE,
    HLEN,
    HOPS: byte;
    XID: longword;
    SECS,
    FLAGS: word;
    CIADDR,
    YIADDR,
    SIADDR,
    GIADDR: TIPv4Address;
    CHADDR: array[0..15] of byte;
    SNAME: array[0..63] of char;
    BOOTFILE: array[0..127] of char;
  end;

procedure DHCPRecv(AData: Pointer; ASocket: TUDPSocketHandle; APacket: PBuffer; ASource: TIPAddress; ASourcePort: word);
  var
    PackSize: SizeInt;
    rd: TBufferWriter;
    xid: LongWord;
    we: LongWord;
    len: Byte;
    t: Byte;
  begin
    PackSize:=APacket^.TotalSize;

    rd:=APacket^.GetWriter;

    repeat
      if rd.ReadByte<>BOOT_REPLY then break;
      if rd.ReadByte<>HT_ETHERNET then break;
      if rd.ReadByte<>6 then break;
      rd.Advance(1);

      xid:=rd.ReadLongWord;

      rd.Advance(236-8);

      if rd.ReadLongWord<>NtoBE(DHCP_COOKIE) then break;

      dec(PackSize, 236+4);

      writeln('DHCP reply');

      // Read options
      while (PackSize>0) do
        begin
          t:=rd.ReadByte;
          if t=$FF then
            break;

          len:=rd.ReadByte;

          writeln(' Option ', t, ' (', len,'): ');

          rd.Advance(len);

          dec(PackSize,2+len);
        end;
    until false;

    //writeln('Got msg');
    APacket^.DecRef;
  end;

function DHCPStartClient(var AIF: TNetif): boolean;
  var
    i: NativeInt;
  begin
    for i := 0 to DHCPClientCount-1 do
      begin
        if Clients[i].State=dsNotUsed then
          begin
            with Clients[i] do
              begin
                if sock=nil then
                  begin
                    sock:=UDPCreateSocket;

                    if sock=nil then
                      exit(false);

                    UDPBind(sock, IPAddress(IPv4_AnyAddr), 68);

                    UDPRecvCallback(sock, @DHCPRecv);
                  end;

                State:=dsInit;
                _IF:=@AIF;
              end;

            exit(true);
          end;
      end;

    exit(false);
  end;

procedure DHCPTick(ADeltaMS: SmallInt);
  var
    i: NativeInt;
    msg: PBuffer;
    writer: TBufferWriter;
    t: TNetResult;
  begin
    for i:=0 to DHCPClientCount-1 do
      begin
        case Clients[i].State of
          dsInit:
            begin
              writeln('DHCP init');

              msg:=AllocateBuffer(sizeof(TDHCPHeader)+4+3+9+5+1+2, plApplication);
              if assigned(msg) then
                begin
                  writer:=msg^.GetWriter;

                  writer.WriteByte(BOOT_REQUEST);
                  writer.WriteByte(HT_ETHERNET);
                  writer.WriteByte(6);
                  writer.WriteByte(0);

                  inc(clients[i].XID);
                  writer.WriteLongWord(clients[i].XID);

                  writer.WriteWord(0);
                  writer.WriteWord(NtoBE(word($8000))); // Broadcast

                  writer.WriteZeros(4*4);

                  writer.Write(Clients[i]._IF^.HWAddr, 6);
                  writer.WriteZeros(10+192);

                  writer.WriteLongword(NtoBE(longword(DHCP_COOKIE)));

                  writer.WriteByte(53); writer.WriteByte(1); writer.WriteByte(1); // DHCPDISCOVER option

                  writer.WriteByte(61); writer.WriteByte(7); // Client identifier
                    writer.WriteByte(1);
                    writer.Write(Clients[i]._IF^.HWAddr, 6);

                  writer.WriteByte(55); writer.WriteByte(3);
                    writer.WriteByte(1); // Subnet
                    writer.WriteByte(3); // Router
                    writer.WriteByte(6); // DNS
                  writer.WriteByte($FF); // End option
                    writer.WriteByte(0);
                    writer.WriteByte(0);

                  t:=UDPSendTo(sock, msg, IPAddress(IPv4_AnyAddr), DHCP_Port);
                  if t<>nrOk then
                    begin
                      writeln('Failed to send DHCP discover: ', t);
                      msg^.DecRef;
                    end
                  else
                    begin
                      writeln('Sent DHCP discover');
                      Clients[i].State:=dsSelecting;
                    end;
                end
              else
                writeln('No buffer');
            end;
        end;
      end;
  end;

end.

