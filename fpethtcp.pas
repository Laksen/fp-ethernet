unit fpethtcp;

interface

{$modeswitch AdvancedRecords}

uses
  fpethbuf, fpethif, fpethtypes;

type
  TTCPAcceptCallback = procedure(ASock: TSocketHandle; AData: pointer; AClient: TSocketHandle; const AIP: TIPAddress; var AAccept: boolean);

  TTCPCallback = procedure(ASock: TSocketHandle; AData: pointer);

  TTCPWriteFlags = set of (twPush);

function TCPCreateSocket: TSocketHandle;
procedure TCPDestroySocket(ASock: TSocketHandle);

procedure TCPSetData(ASock: TSocketHandle; AData: pointer);
procedure TCPAcceptCallback(ASock: TSocketHandle; AFunc: TTCPAcceptCallback);
procedure TCPRecvCallback(ASock: TSocketHandle; AFunc: TTCPCallback);
procedure TCPConnectCallback(ASock: TSocketHandle; AFunc: TTCPCallback);

function TCPBind(ASock: TSocketHandle; const AAddr: TIPAddress; APort: word): TNetResult;
function TCPListen(ASock: TSocketHandle): TNetResult;
function TCPConnect(ASock: TSocketHandle; const AAddr: TIPAddress; APort: word): TNetResult;

function TCPGetDataAvailable(ASock: TSocketHandle): SizeInt;
function TCPGetData(ASock: TSocketHandle): PBuffer;
function TCPRead(ASock: TSocketHandle; ABytes: SizeInt): TNetResult;

function TCPGetSendAvailable(ASock: TSocketHandle): SizeInt;
function TCPWrite(ASock: TSocketHandle; const AData; ASize: SizeInt): SizeInt;

// Stack functions
procedure TCPInput(var AIF: TNetif; APacket: PBuffer; const ASource, ADest: TIPAddress);

procedure TCPTick(ADeltaMS: NativeInt);

implementation

uses
  fpethip, fpethcfg;

{$packset 1}

type
  TTCPFlag = (tfFin, tfSyn, tfRst, tfPsh, tfAck, tfUrg);
  TTCPFlags = set of TTCPFlag;

  TTCPState = (
    tsClosed,
    tsListen, tsSynSent, tsSynReceived, tsEstablished,
    tsFinWait1, tsFinWait2, tsCloseWait, tsClosing,
    tsLastAck, tsTimeWait);

  TTCPSocketState = (tssUnbound, tssBound, tssConnected);

  PTCPSocket = ^TTCPSocket;
  TTCPSocket = record
    Next: PTCPSocket;

    Data: pointer;
    SockState: TTCPSocketState;

    AcceptClb: TTCPAcceptCallback;
    RecvClb,
    ConnectClb: TTCPCallback;

    // Src=local
    Src,
    Dest: TIPAddress;
    SPort, DPort: word;

    State: TTCPState;
    Timer: longint;

    // TCB
    RecvBuff: PBuffer;
    SndUna,SndNxt,SndWnd: longword;
    RcvNxt,RcvWnd: longword;

    function InRecvWnd(ASeq: longword): boolean;
  end;

const
  TCP_OPT_MSS = 2;
  TCP_OPT_WINDOW_SCALING = 3;

var
  Socks: PTCPSocket = nil;
  PortCounter: word = 1;

function FindSock(APort: word): PTCPSocket;
  var
    p: PTCPSocket;
  begin
    p:=Socks;
    while assigned(p) do
      begin
        if (p^.SockState in [tssBound,tssConnected]) and
           (p^.sport=APort) and
           AddrMatches(p^.Src, IPv4_AnyAddr) then
          exit(p);

        p:=p^.Next;
      end;
    exit(nil);
  end;

function FindSock(const AAddr: TIPAddress; APort: word): PTCPSocket;
  var
    p: PTCPSocket;
  begin
    p:=Socks;
    while assigned(p) do
      begin
        if (p^.SockState in [tssBound,tssConnected]) and
           (p^.sport=APort) and
           (AddrMatches(AAddr, p^.Src) or
            AddrMatches(p^.Src, IPv4_AnyAddr)) then
          exit(p);

        p:=p^.Next;
      end;
    exit(nil);
  end;

function GetFreePort: word;
  var
    tmp: Word;
  begin
    while true do
      begin
        tmp:=PortCounter;
        inc(PortCounter);
        if FindSock(tmp)=nil then
          exit(tmp);
      end;

    exit(0);
  end;

function TCPSendMsg(const ADst, ASrc: TIPAddress; ADstPort, ASrcPort: word; ASeq, AAck: longword; AWnd: word; AFlags: TTCPFlags; AOptions, AData: PBuffer): TNetResult;
  var
    t: PBuffer;
    wr, cp: TBufferWriter;
    l: byte;
    Sum: Word;
    ts: SizeInt;
  begin
    l:=5;
    if Assigned(AOptions) and Assigned(AData) then
      begin
        l:=(AOptions^.TotalSize shr 2)+5;

        t:=AOptions;
        t:=t^.Concat(AData);
        t:=t^.Expand(20,0);
      end
    else if assigned(AOptions) then
      begin
        l:=(AOptions^.TotalSize shr 2)+5;

        t:=AOptions^.Expand(20,0);
      end
    else
      t:=AllocateBuffer(20);

    if not assigned(t) then
      exit(nrOutOfMem);

    wr:=t^.GetWriter;

    wr.WriteWord(NtoBE(ASrcPort));
    wr.WriteWord(NtoBE(ADstPort));

    wr.WriteLongword(NtoBE(ASeq));
    wr.WriteLongword(NtoBE(AAck));

    wr.writebyte((l and $F) shl 4);
    wr.WriteByte(byte(AFlags));

    wr.WriteWord(NtoBE(AWnd));

    cp:=wr;
    wr.WriteWord(0); // Checksum
    wr.WriteWord(0); // Urgent pointer

    ts:=t^.TotalSize;
    Sum:=CalcTCPPseudoChecksum(ASrc.V4, ADst.V4, ts);
    Sum:=CalcChecksum(t, ts, sum);
    cp.WriteWord(NtoBE(not sum));

    exit(IPOutput(IPPROTO_TCP, ADst, t));
  end;

function TCPSendMsg(ASock: PTCPSocket; ASeq, AAck: longword; AWnd: word; AFlags: TTCPFlags; AOptions, AData: PBuffer): TNetResult;
  begin
    exit(TCPSendMsg(ASock^.Dest, asock^.Src, ASock^.DPort, ASock^.SPort, ASeq, AAck, AWnd, AFlags, AOptions, AData));
  end;

function TCPCreateSocket: TSocketHandle;
  var
    tmp: PTCPSocket;
  begin
    tmp:=PTCPSocket(AllocMem(sizeof(TTCPSocket)));

    tmp^.Next:=Socks;
    Socks:=tmp;

    TCPCreateSocket:=tmp;
  end;

procedure TCPDestroySocket(ASock: TSocketHandle);
  var
    p: PTCPSocket;
  begin
    if ASock=Socks then
      Socks:=PTCPSocket(ASock)^.Next
    else
      begin
        p:=Socks;
        while assigned(p) do
          begin
            if p^.Next=ASock then
              begin
                p^.Next:=PTCPSocket(ASock)^.Next;
                break;
              end;
          end;
      end;

    Freemem(ASock);
  end;

procedure TCPSetData(ASock: TSocketHandle; AData: pointer);
  begin
    PTCPSocket(ASock)^.Data:=AData;
  end;

procedure TCPAcceptCallback(ASock: TSocketHandle; AFunc: TTCPAcceptCallback);
  begin
    PTCPSocket(ASock)^.AcceptClb:=AFunc;
  end;

procedure TCPRecvCallback(ASock: TSocketHandle; AFunc: TTCPCallback);
  begin
    PTCPSocket(ASock)^.RecvClb:=AFunc;
  end;

procedure TCPConnectCallback(ASock: TSocketHandle; AFunc: TTCPCallback);
  begin
    PTCPSocket(ASock)^.ConnectClb:=AFunc;
  end;

function TCPBind(ASock: TSocketHandle; const AAddr: TIPAddress; APort: word): TNetResult;
  var
    sck: PTCPSocket;
  begin
    sck:=FindSock(APort);
    if assigned(sck) and (sck<>ASock) then
      exit(nrPortOccupied);

    if PTCPSocket(ASock)^.SockState=tssUnbound then
      PTCPSocket(ASock)^.SockState:=tssBound;

    PTCPSocket(ASock)^.Src:=AAddr;
    PTCPSocket(ASock)^.SPort:=APort;

    exit(nrOk);
  end;

function TCPListen(ASock: TSocketHandle): TNetResult;
  begin
    if PTCPSocket(ASock)^.SockState<>tssBound then
      exit(nrNotBound);

    PTCPSocket(ASock)^.State:=tsListen;

    PTCPSocket(ASock)^.SndNxt:=GetRandom32(ASock);
    PTCPSocket(ASock)^.SndUna:=PTCPSocket(ASock)^.SndNxt;

    PTCPSocket(ASock)^.RcvWnd:=TCPMaxReceiveWindow;

    exit(nrOk);
  end;

function TCPConnect(ASock: TSocketHandle; const AAddr: TIPAddress; APort: word): TNetResult;
  begin
    exit(nrNotSupported);
  end;

function TCPGetDataAvailable(ASock: TSocketHandle): SizeInt;
  begin
    if assigned(PTCPSocket(ASock)^.RecvBuff) then
      result:=PTCPSocket(ASock)^.RecvBuff^.TotalSize
    else
      result:=0;
  end;

function TCPGetData(ASock: TSocketHandle): PBuffer;
  begin
    result:=PTCPSocket(ASock)^.RecvBuff;
  end;

function TCPRead(ASock: TSocketHandle; ABytes: SizeInt): TNetResult;
  begin
    if assigned(PTCPSocket(ASock)^.RecvBuff) then
      begin
        PTCPSocket(ASock)^.RecvBuff:=PTCPSocket(ASock)^.RecvBuff^.Contract(ABytes,0);
        result:=nrOk;
      end
    else
      result:=nrOutOfMem;
  end;

function TCPGetSendAvailable(ASock: TSocketHandle): SizeInt;
  begin

  end;

function TCPWrite(ASock: TSocketHandle; const AData; ASize: SizeInt): SizeInt;
  begin

  end;

function TCPDataInput(var sock: PTCPSocket; Seq: longword; APacket: PBuffer; IsFin: boolean): TNetResult;
  var
    Diff: SizeInt;
  begin
    if assigned(APacket) then
      begin
        if (seq = sock^.RcvNxt) and
           (sock^.RcvWnd > 0) then
          begin
            Diff:=sock^.RcvWnd-APacket^.TotalSize;
            if Diff<0 then
              APacket:=APacket^.Contract(0, -Diff);

            if assigned(APacket) then
              begin
                sock^.RcvNxt:=Seq+APacket^.TotalSize;

                if assigned(sock^.RecvBuff) then
                  begin
                    sock^.RecvBuff^.ConcatSmart(APacket);
                    APacket^.DecRef;
                  end
                else
                  sock^.RecvBuff:=APacket;

                if assigned(sock^.RecvClb) then
                  sock^.RecvClb(sock, sock^.Data);

                if assigned(sock^.RecvBuff) then
                  sock^.RcvWnd:=TCPMaxReceiveWindow-sock^.RecvBuff^.TotalSize
                else
                  sock^.RcvWnd:=TCPMaxReceiveWindow;
              end;

            if IsFin then
              inc(sock^.RcvNxt);

            exit(TCPSendMsg(sock, sock^.SndNxt, sock^.RcvNxt, sock^.RcvWnd, [tfAck], nil, nil));
          end
        else
          begin
            writeln('Got packet outside window (',sock^.RcvNxt,'->',sock^.RcvNxt+sock^.RcvWnd,') => ', seq);
            APacket^.DecRef;
          end;
      end
    else if IsFin then
      sock^.RcvNxt:=Seq+1;

    exit(TCPSendMsg(sock, sock^.SndNxt, sock^.RcvNxt, sock^.RcvWnd, [tfAck], nil, nil));
  end;

function TCPGetConnectOptions(ASock: PTCPSocket): PBuffer;
  var
    res: PBuffer;
    wr: TBufferWriter;
  begin
    res:=AllocateBuffer(4, plPhy);

    if assigned(res) then
      begin
        wr:=res^.GetWriter;

        wr.WriteByte(TCP_OPT_MSS);
        wr.writebyte(4);
        wr.WriteWord(NtoBE(word(TCPMSS)));
      end;

    result:=res;
  end;

procedure TCPInput(var AIF: TNetif; APacket: PBuffer; const ASource, ADest: TIPAddress);
  var
    rd: TBufferWriter;
    Offset: SmallInt;
    SPort, DPort, Wnd, CheckSum: Word;
    Seq, Ack: longword;
    Flags: TTCPFlags;
    f: TTCPFlag;
    tf: Byte;
    sock: PTCPSocket;
    opts: PBuffer;
  begin
    rd:=APacket^.GetWriter;

    SPort:=BEtoN(rd.ReadWord);
    DPort:=BEtoN(rd.ReadWord);

    Seq:=BEtoN(rd.ReadLongWord);
    Ack:=BEtoN(rd.ReadLongWord);

    Offset:=((rd.ReadByte shr 4) and $F);
    tf:=rd.readbyte;
    Flags:=TTCPFlags(tf);

    Wnd:=BEtoN(rd.ReadWord);

    CheckSum:=BEtoN(rd.ReadWord);
    rd.Advance(2); // Urgent pointer

    // Options

    {writeln('TCP packet from ', GetStr(ASource),':',SPort,' -> ', GetStr(ADest),':',DPort);
    for f in flags do
      write(f,',');
    writeln(' - ', hexStr(tf,2), '. Offset: ', Offset*4);}

    sock:=FindSock(ADest, DPort);

    if assigned(sock) then
      begin
        case sock^.State of
          tsListen:
            begin
              if flags=[tfSyn] then
                begin
                  opts:=TCPGetConnectOptions(sock);

                  Sock^.Dest:=ASource;
                  sock^.DPort:=SPort;

                  sock^.Src:=ADest;
                  sock^.SPort:=DPort;

                  sock^.RcvNxt:=Seq+1;
                  sock^.SndWnd:=Wnd;

                  if TCPSendMsg(sock, sock^.SndNxt, sock^.RcvNxt, sock^.RcvWnd, [tfSyn, tfAck], opts, nil)=nrOk then
                    sock^.State:=tsSynReceived;
                end;
            end;
          tsSynReceived:
            begin
              if flags=[tfRst] then
                begin
                  sock^.Dest:=IPAddress(IPv4_AnyAddr);
                  sock^.DPort:=0;

                  sock^.State:=tsListen;
                end
              else if flags=[tfAck] then
                begin
                  sock^.State:=tsEstablished;
                end;
            end;
          tsEstablished:
            begin
              if tfFin in flags then
                begin
                  APacket:=APacket^.Contract(Offset*4,0);

                  if TCPDataInput(sock, seq, APacket, true)=nrOk then
                    begin
                      // We were closed by other end
                      sock^.state:=tsCloseWait;
                    end;

                  exit;
                end
              else if tfRst in flags then
                begin
                  // TODO: Advice user that the socket is closed
                  sock^.SockState:=tssUnbound;
                  sock^.State:=tsClosed;
                end
              else
                begin
                  APacket:=APacket^.Contract(Offset*4,0);

                  TCPDataInput(sock, Seq, APacket, false);

                  exit;
                end;
            end;
          tsLastAck:
            begin
              if tfAck in flags then
                TCPDestroySocket(sock);
            end;
        end;
      end
    else
      TCPSendMsg(ASource, ADest, SPort, DPort, 0, seq+1, 0, [tfAck, tfRst], nil, nil);

    APacket^.DecRef;
  end;

procedure TCPTick(ADeltaMS: NativeInt);
  begin

  end;

function TTCPSocket.InRecvWnd(ASeq: longword): boolean;
  begin
    result:=(ASeq-RcvNxt)<RcvWnd;
  end;

end.

