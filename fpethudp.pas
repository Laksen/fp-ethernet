unit fpethudp;

interface

uses
  fpethif, fpethbuf, fpethtypes;

type
  TUDPSocketHandle = type pointer;

  TUDPErrorCallback = procedure(AData: Pointer; ASocket: TUDPSocketHandle);
  TUDPRecvCallback = procedure(AData: Pointer; ASocket: TUDPSocketHandle; APacket: PBuffer; ASource: TIPAddress; ASourcePort: word);

function UDPCreateSocket: TUDPSocketHandle;
procedure UDPDestroySocket(ASock: TUDPSocketHandle);

procedure UDPSetData(ASock: TUDPSocketHandle; AData: pointer);
procedure UDPErrorCallback(ASock: TUDPSocketHandle; AFunc: TUDPErrorCallback);
procedure UDPRecvCallback(ASock: TUDPSocketHandle; AFunc: TUDPRecvCallback);

function UDPBind(ASock: TUDPSocketHandle; const AAddr: TIPAddress; APort: word): TNetResult;
function UDPConnect(ASock: TUDPSocketHandle; const AAddr: TIPAddress; APort: word): TNetResult;

function UDPSend(ASock: TUDPSocketHandle; APacket: PBuffer): TNetResult;
function UDPSendTo(ASock: TUDPSocketHandle; APacket: PBuffer; const ADest: TIPAddress; ADestPort: word): TNetResult;

// Stack functions
function UDPOutput(var AIF: TNetif; APacket: PBuffer; ASourcePort, ADestPort: word; const ADest: TIPAddress): TNetResult;
procedure UDPv4Input(var AIF: TNetif; APacket: PBuffer; const ASource, ADest: TIPv4Address);

implementation

uses
  fpethip;

type
  TUDPSocketState = (usUnbound, usBound, usConnected);

  PUDPSocket = ^TUDPSocket;
  TUDPSocket = record
    Next: PUDPSocket;

    State: TUDPSocketState;

    LocalPort: word;
    LocalIP: TIPAddress;

    RemotePort: word;
    RemoteIP: TIPAddress;

    Data: pointer;
    ErrorClb: TUDPErrorCallback;
    RecvClb: TUDPRecvCallback;
  end;

var
  Socks: PUDPSocket = nil;
  PortCounter: word = 1;

type
  TUDPHeader = packed record
    Source,
    Dest,
    Length,
    Checksum: word;
  end;

function FindSock(APort: word): PUDPSocket;
  var
    p: PUDPSocket;
  begin
    p:=Socks;
    while assigned(p) do
      begin
        if (p^.State in [usBound,usConnected]) and
           (p^.LocalPort=APort) then
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

function UDPCreateSocket: TUDPSocketHandle;
  var
    tmp: PUDPSocket;
  begin
    tmp:=PUDPSocket(AllocMem(sizeof(TUDPSocket)));

    tmp^.Next:=Socks;
    Socks:=tmp;

    UDPCreateSocket:=tmp;
  end;

procedure UDPDestroySocket(ASock: TUDPSocketHandle);
  var
    p: PUDPSocket;
  begin
    if ASock=Socks then
      Socks:=PUDPSocket(ASock)^.Next
    else
      begin
        p:=Socks;
        while assigned(p) do
          begin
            if p^.Next=ASock then
              begin
                p^.Next:=PUDPSocket(ASock)^.Next;
                break;
              end;
          end;
      end;

    Freemem(ASock);
  end;

procedure UDPSetData(ASock: TUDPSocketHandle; AData: pointer);
  begin
    PUDPSocket(ASock)^.Data:=AData;
  end;

procedure UDPErrorCallback(ASock: TUDPSocketHandle; AFunc: TUDPErrorCallback);
  begin
    PUDPSocket(ASock)^.ErrorClb:=AFunc;
  end;

procedure UDPRecvCallback(ASock: TUDPSocketHandle; AFunc: TUDPRecvCallback);
  begin
    PUDPSocket(ASock)^.RecvClb:=AFunc;
  end;

function UDPBind(ASock: TUDPSocketHandle; const AAddr: TIPAddress; APort: word): TNetResult;
  var
    sck: PUDPSocket;
  begin
    sck:=FindSock(APort);
    if assigned(sck) and (sck<>ASock) then
      exit(nrPortOccupied);

    if PUDPSocket(ASock)^.State=usUnbound then
      PUDPSocket(ASock)^.State:=usBound;

    PUDPSocket(ASock)^.LocalIP:=AAddr;
    PUDPSocket(ASock)^.LocalPort:=APort;

    exit(nrOk);
  end;

function UDPConnect(ASock: TUDPSocketHandle; const AAddr: TIPAddress; APort: word): TNetResult;
  begin
    if PUDPSocket(ASock)^.State<>usConnected then
      begin
        if PUDPSocket(ASock)^.State=usUnbound then
          UDPBind(ASock, IPAddress(IPv4_AnyAddr), GetFreePort);

        PUDPSocket(ASock)^.State:=usConnected;
      end;

    PUDPSocket(ASock)^.RemoteIP:=AAddr;
    PUDPSocket(ASock)^.RemotePort:=APort;

    exit(nrOk);
  end;

function UDPSend(ASock: TUDPSocketHandle; APacket: PBuffer): TNetResult;
  begin
    if PUDPSocket(ASock)^.State<>usConnected then
      exit(nrNotConnected);

    exit(UDPSendTo(ASock, APacket, PUDPSocket(ASock)^.RemoteIP, PUDPSocket(ASock)^.RemotePort));
  end;

function UDPSendTo(ASock: TUDPSocketHandle; APacket: PBuffer; const ADest: TIPAddress; ADestPort: word): TNetResult;
  var
    AIF: TNetif;
  begin
    if not FindRoute(ADest, AIF) then
      exit(nrNoRoute);

    Exit(UDPOutput(AIF, APacket, PUDPSocket(ASock)^.LocalPort, ADestPort, ADest));
  end;

function UDPOutput(var AIF: TNetif; APacket: PBuffer; ASourcePort, ADestPort: word; const ADest: TIPAddress): TNetResult;
  var
    Header: TUDPHeader;
    PackSize: SizeInt;
  begin
    if ADest.AddrTyp=atIPv4 then
      begin
        PackSize:=APacket^.TotalSize;
        APacket:=APacket^.Expand(SizeOf(TUDPHeader), 0);
        if assigned(APacket) then
          begin
            Header.Dest:=NtoBE(ADestPort);
            Header.Source:=NtoBE(ASourcePort);
            Header.Length:=NtoBE(sizeof(Header)+PackSize);
            APacket^.Write(Header, SizeOf(Header), 0);

            Header.Checksum:=NtoBE(CalcUDPIPv4Checksum(CalcChecksum(APacket, Sizeof(Header)+PackSize), AIF.IPv4, ADest.V4, sizeof(Header)+PackSize));
            APacket^.Write(Header.Checksum, SizeOf(word), 6);

            exit(IPOutput(AIF, IPPROTO_UDP, ADest, APacket));
          end
        else
          exit(nrOutOfMem);
      end
    else
      begin
        // IPv6
        APacket^.DecRef;
        exit(nrNotSupported);
      end;
  end;

procedure UDPv4Input(var AIF: TNetif; APacket: PBuffer; const ASource, ADest: TIPv4Address);
  var
    Header: TUDPHeader;
    ChkSum: Word;
    len: Word;
    Sock: PUDPSocket;
    Trailer: SizeInt;
    Prt: Word;
  begin
    APacket^.Read(Header, sizeof(Header), 0);

    len:=BEtoN(Header.Length);
    if (Header.Checksum<>0) then
      begin
        ChkSum:=CalcChecksum(APacket, len);
        ChkSum:=CalcUDPIPv4Checksum(ChkSum, ASource, ADest, len);

        if ChkSum<>$FFFF then
          begin
            APacket^.DecRef;
            exit;
          end;
      end;

    Prt:=BEtoN(Header.Dest);
    Sock:=FindSock(Prt);
    if assigned(Sock) and
       assigned(Sock^.RecvClb) then
      begin
        Trailer:=APacket^.TotalSize-8-len;
        if Trailer<0 then Trailer:=0;

        writeln('Contracting: ', 8, '-', Trailer);

        APacket:=APacket^.Contract(8, Trailer);

        if assigned(APacket) then
          Sock^.RecvClb(Sock^.Data, Sock, APacket, IPAddress(ASource), Prt);
      end
    else
      APacket^.DecRef;
  end;

end.

