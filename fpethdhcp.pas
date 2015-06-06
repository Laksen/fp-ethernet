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
    T0,
    T1, T2: longint;
    XID: longword;
    _IF: PNetif;
    Server,
    Wanted: TIPv4Address;
  end;

const
  DHCP_Port = 67;

  BOOT_REQUEST = 1;
  BOOT_REPLY = 2;

  HT_ETHERNET = 1;

  DHCP_COOKIE = $63825363;

  DMT_DISCOVER = 1;
  DMT_OFFER = 2;
  DMT_REQUEST = 3;
  DMT_DECLINE = 4;
  DMT_ACK = 5;
  DMT_NAK = 6;
  DMT_RELEASE = 7;

  DO_PAD = 0;
  DO_SUBNET_MASK = 1;
  DO_ROUTER = 3;
  DO_NAME_SERVER = 5;
  DO_DOMAIN_NAME_SERVER = 6;
  DO_DEFAULT_IP_TTL = 23;
  DO_REQUESTED_IP = 50;
  DO_IP_LEASE_TIME = 51;
  DO_DHCP_MESSAGE_TYPE = 53;
  DO_SERVER_ID = 54;
  DO_PARAM_REQ_LIST = 55;
  DO_RENEW_TIME = 58;
  DO_REBINDING_TIME = 59;
  DO_CLIENT_ID = 61;
  DO_END_OPTION = 255;

var
  Clients: array[0..DHCPClientCount-1] of TDHCPClient;
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

procedure SendRequest(AClient: NativeInt; AUnicast: boolean);
  var
    msg: PBuffer;
    writer: TBufferWriter;
    t: TNetResult;
  begin
    msg:=AllocateBuffer(sizeof(TDHCPHeader)+4+3+6+6+2, plApplication);
    if assigned(msg) then
      begin
        writer:=msg^.GetWriter;

        writer.WriteByte(BOOT_REQUEST);
        writer.WriteByte(HT_ETHERNET);
        writer.WriteByte(6);
        writer.WriteByte(0);

        writer.WriteLongWord(clients[AClient].XID);

        writer.WriteWord(0);
        if AUnicast then
          writer.WriteWord(0)
        else
          writer.WriteWord(NtoBE(word($8000))); // Broadcast

        writer.WriteLongword(Clients[AClient]._IF^.IPv4.val);
        writer.WriteZeros(4);
        writer.WriteLongword(Clients[AClient].Server.val);
        writer.WriteZeros(4);

        writer.Write(Clients[AClient]._IF^.HWAddr, 6);
        writer.WriteZeros(10+192);

        writer.WriteLongword(NtoBE(longword(DHCP_COOKIE)));

        writer.WriteByte(DO_DHCP_MESSAGE_TYPE); writer.WriteByte(1);
          writer.WriteByte(DMT_REQUEST);

        writer.WriteByte(DO_REQUESTED_IP); writer.WriteByte(4);
          writer.WriteLongword(Clients[AClient].Wanted.val);

        writer.WriteByte(DO_SERVER_ID); writer.WriteByte(4);
          writer.WriteLongword(Clients[AClient].Server.val);

        writer.WriteByte(DO_END_OPTION); // End option
          writer.WriteByte(0);

        if AUnicast then
          t:=UDPSendTo(sock, msg, IPAddress(Clients[AClient].Server), DHCP_Port)
        else
          t:=UDPSendTo(sock, msg, IPAddress(IPv4_AnyAddr), DHCP_Port);
        if t<>nrOk then
          writeln('Failed to send DHCP request: ', t);
      end;
  end;

procedure DHCPRecv(AData: Pointer; ASocket: TUDPSocketHandle; APacket: PBuffer; ASource: TIPAddress; ASourcePort: word);
  var
    PackSize,ps2: SizeInt;
    rd,rd2: TBufferWriter;
    xid: LongWord;
    MsgType, len, t: Byte;
    yiaddr,siaddr: LongWord;
    claddr: THWAddress;
    i, cl: NativeInt;
    lt: LongWord;
  begin
    PackSize:=APacket^.TotalSize;

    if PackSize>=sizeof(TDHCPHeader) then
      begin
        rd:=APacket^.GetWriter;

        repeat
          if rd.ReadByte<>BOOT_REPLY then break;
          if rd.ReadByte<>HT_ETHERNET then break;
          if rd.ReadByte<>6 then break;
          rd.Advance(1);

          xid:=rd.ReadLongWord;

          rd.advance(8); // Skip SECS+FLAGS+CIADDR
          yiaddr:=rd.ReadLongWord;
          siaddr:=rd.ReadLongWord;
          rd.advance(4); // Skip GIADDR
          rd.Read(claddr, 6);

          cl:=-1;
          for i:=0 to DHCPClientCount-1 do
            begin
              if (Clients[i].XID=xid) and
                 (clients[i]._IF<>nil) and
                 (clients[i].State in [dsSelecting,dsRequesting,dsRebinding,dsRenewing]) and
                 AddrMatches(clients[i]._IF^.HWAddr, claddr) then
                begin
                  cl:=i;
                  break;
                end;
            end;

          if cl<0 then break;

          rd.Advance(236-8-(8+4+8+6));

          if rd.ReadLongWord<>NtoBE(DHCP_COOKIE) then break;

          dec(PackSize, 236+4);

          rd2:=rd;
          ps2:=PackSize;

          // Scan through options to find the DHCP message type
          MsgType:=0;
          while (ps2>0) do
            begin
              t:=rd2.ReadByte;
              if t=0 then
                begin
                  dec(ps2);
                  continue;
                end
              else if t=$FF then
                break;

              len:=rd2.ReadByte;

              case t of
                DO_DHCP_MESSAGE_TYPE: MsgType:=rd2.ReadByte;
              end;

              rd2.Advance(len);

              dec(ps2,2+len);
            end;

          case MsgType of
            DMT_OFFER:
              begin
                if clients[cl].State<>dsSelecting then
                  break;

                APacket^.DecRef;
                SendRequest(cl, false);

                clients[cl].State:=dsRequesting;

                clients[cl].T1:=DHCPRequestRetryTimeout;
                clients[cl].T2:=DHCPRequestTimeout;

                clients[cl].Wanted.val:=yiaddr;
                clients[cl].Server.val:=siaddr;

                exit;
              end;
            DMT_ACK:
              begin
                if clients[cl].State<>dsRequesting then
                  break;

                if clients[cl].Server.val<>siaddr then
                  break;

                clients[cl]._IF^.IPv4.val:=yiaddr;
                clients[cl].State:=dsBound;
              end;
            DMT_NAK:
              begin
                if not (clients[cl].State in [dsRequesting,dsRebinding,dsRenewing]) then
                  break;

                if clients[cl].Server.val<>siaddr then
                  break;

                clients[cl].State:=dsInit;
              end
            else
              break;
          end;

          lt:=0;

          // Read options
          while (PackSize>0) do
            begin
              t:=rd.ReadByte;
              if t=0 then
                begin
                  dec(PackSize);
                  continue;
                end
              else if t=$FF then
                break;

              len:=rd.ReadByte;

              case t of
                DO_DEFAULT_IP_TTL: Clients[cl]._IF^.IPTTL:=rd.ReadByte;

                DO_SUBNET_MASK: Clients[cl]._IF^.SubMaskv4.val:=rd.ReadLongWord;

                DO_IP_LEASE_TIME: lt:=BEtoN(rd.ReadLongWord);
                DO_RENEW_TIME: Clients[cl].T1:=BEtoN(rd.ReadLongWord);
                DO_REBINDING_TIME: Clients[cl].T2:=BEtoN(rd.ReadLongWord);

                else
                  rd.Advance(len);
              end;

              dec(PackSize,2+len);
            end;

          if lt<=0 then
            lt:=clients[cl].T2*2;

          Clients[cl].T0:=lt;
        until true;
      end;

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
              clients[i]._IF^.IPv4:=IPv4Address(0,0,0,0);

              writeln('DHCP init');

              msg:=AllocateBuffer(sizeof(TDHCPHeader)+4+3+9+5+2+1, plApplication);
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

                  writer.WriteByte(DO_DHCP_MESSAGE_TYPE); writer.WriteByte(1); // DHCPDISCOVER option
                    writer.WriteByte(DMT_DISCOVER);

                  writer.WriteByte(DO_CLIENT_ID); writer.WriteByte(7); // Client identifier
                    writer.WriteByte(1);
                    writer.Write(Clients[i]._IF^.HWAddr, 6);

                  writer.WriteByte(DO_PARAM_REQ_LIST); writer.WriteByte(3);
                    writer.WriteByte(1); // Subnet
                    writer.WriteByte(3); // Router
                    writer.WriteByte(6); // DNS
                  writer.WriteByte(DO_END_OPTION); // End option
                    writer.WriteByte(0);
                    writer.WriteByte(0);

                  t:=UDPSendTo(sock, msg, IPAddress(IPv4_AnyAddr), DHCP_Port);
                  if t<>nrOk then
                    begin
                      writeln('Failed to send DHCP discover: ', t);
                    end
                  else
                    begin
                      writeln('Sent DHCP discover');
                      Clients[i].State:=dsSelecting;
                      clients[i].T1:=DHCPInitRetryTime;
                    end;
                end
              else
                writeln('No buffer');
            end;
          dsSelecting:
            begin
              dec(clients[i].T1,ADeltaMS);
              if clients[i].T1<=0 then
                clients[i].State:=dsInit;
            end;
          dsRequesting:
            begin
              dec(clients[i].T1,ADeltaMS);
              dec(clients[i].T2,ADeltaMS);

              if clients[i].T2<=0 then
                clients[i].State:=dsInit
              else if clients[i].T1<=0 then
                begin
                  SendRequest(i,false);
                  clients[i].T1:=DHCPRequestRetryTimeout;
                end;
            end;
          dsBound:
            begin
              dec(clients[i].T0,ADeltaMS);
              dec(clients[i].T1,ADeltaMS);
              dec(clients[i].T2,ADeltaMS);
              
              if clients[i].T1<0 then
                begin
                  clients[i].State:=dsRebinding;
                  clients[i].T1:=DHCPRequestRetryTimeout;

                  SendRequest(i, true);
                end;
            end;
          dsRebinding:
            begin
              dec(clients[i].T0,ADeltaMS);
              dec(clients[i].T1,ADeltaMS);
              dec(clients[i].T2,ADeltaMS);

              if clients[i].T2<0 then
                begin
                  clients[i].State:=dsRenewing;
                  clients[i].T1:=DHCPRequestRetryTimeout;

                  SendRequest(i, false);
                end
              else if clients[i].T1<0 then
                begin
                  clients[i].T1:=DHCPRequestRetryTimeout;

                  SendRequest(i, true);
                end;
            end;
          dsRenewing:
            begin

            end;
        end;
      end;
  end;

end.

