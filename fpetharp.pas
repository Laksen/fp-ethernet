unit fpetharp;

interface

uses
  fpethif, fpethtypes, fpethbuf;

type
  TArpResult = (arSuccess, arLooking);

procedure ARPSendGratuitous(var AIF: TNetif);

function ARPLookupIPv4(const AAddress: TIPv4Address; var AHWAddress: THWAddress): TArpResult;

// Called once per second
procedure ARPTick(ADelta: LongInt);

procedure ARPInput(var AIF: TNetif; APacket: PBuffer);

implementation

uses
  fpethcfg;

type
  TARPIPv4Header = packed record
    HType,
    PType: word;
    HLen,
    PLen: byte;
    Oper: word;
    SHA: THWAddress;
    SPA: TIPv4Address;
    THA: THWAddress;
    TPA: TIPv4Address;
  end;

  TArpState = (asUnused, asIncomplete, asComplete);

  TIPCache = record
    State: TArpState;
    TTL: LongInt;
    IP: TIPAddress;
    Addr: THWAddress;
  end;

const
  HTYPE_ETHER = 1;

  PTYPE_IPv4 = $0800;

  HLEN_ETHER = 6;
  PLEN_IPv4 = 4;

  OPER_REQUEST = 1;
  OPER_REPLY = 2;

var
  IPCache: array[0..ARPIPCacheSize-1] of TIPCache;

function FindCacheIndex: SizeInt;
  var
    i,bestI,bestCI: SizeInt;
  begin
    bestI:=-1;
    bestCI:=-1;

    for i := 0 to ARPIPCacheSize-1 do
      if IPCache[i].State=asUnused then
        exit(i)
      else if IPCache[i].State=asIncomplete then
        begin
          if bestI<0 then
            bestI:=i
          else if IPCache[i].TTL<IPCache[bestI].TTL then
            bestI:=i;
        end
      else
        begin
          if bestCI<0 then
            bestCI:=i
          else if IPCache[i].TTL<IPCache[bestCI].TTL then
            bestCI:=i;
        end;

    if bestI>=0 then
      exit(bestI)
    else if bestCI>=0 then
      exit(bestCI)
    else
      exit(0);
  end;

procedure SendRequest(AIndex: SizeInt);
  var
    Pack: PBuffer;
    Header: TARPIPv4Header;
    _IF: TNetif;
  begin
    IPCache[AIndex].TTL:=ARPCacheRetryTTL;

    if FindRoute(IPCache[AIndex].IP, _IF) then
      begin
        Pack:=AllocateBuffer(sizeof(TARPIPv4Header), plLink);
        if assigned(Pack) then
          begin
            Header.HType:=NtoBE(HTYPE_ETHER);
            Header.HLen:=HLEN_ETHER;
            Header.PType:=NtoBE(PTYPE_IPv4);
            Header.PLen:=PLEN_IPv4;

            Header.Oper:=NtoBE(OPER_REQUEST);

            Header.SHA:=_IF.HWAddr;
            Header.SPA:=_IF.IPv4;

            Header.THA:=BroadcastAddr;
            Header.TPA:=IPCache[AIndex].IP.V4;

            Pack^.Write(Header, sizeof(header), 0);

            EthOutput(_IF, BroadcastAddr, ET_ARP, Pack);
          end;
      end;
  end;

procedure ARPSendGratuitous(var AIF: TNetif);
  var
    Pack: PBuffer;
    Header: TARPIPv4Header;
  begin
    Pack:=AllocateBuffer(sizeof(TARPIPv4Header), plLink);
    if assigned(Pack) then
      begin
        Header.HType:=NtoBE(HTYPE_ETHER);
        Header.HLen:=HLEN_ETHER;
        Header.PType:=NtoBE(PTYPE_IPv4);
        Header.PLen:=PLEN_IPv4;

        Header.Oper:=NtoBE(OPER_REQUEST);

        Header.SHA:=AIF.HWAddr;
        Header.SPA:=AIF.IPv4;

        Header.THA:=BroadcastAddr;
        Header.TPA:=AIF.IPv4;

        Pack^.Write(Header, sizeof(header), 0);

        EthOutput(AIF, BroadcastAddr, ET_ARP, Pack);
      end;
  end;

function ARPLookupIPv4(const AAddress: TIPv4Address; var AHWAddress: THWAddress): TArpResult;
  var
    i: NativeInt;
  begin
    for i := 0 to ARPIPCacheSize-1 do
      begin
        if IPCache[i].State=asComplete then
          begin
            if AddrMatches(IPCache[i].IP, AAddress) then
              begin
                AHWAddress:=IPCache[i].Addr;
                if ARPCacheRestartTTLOnUse then
                  IPCache[i].TTL:=ARPCacheCompleteTTL;
                exit(arSuccess);
              end;
          end
        else if IPCache[i].State=asIncomplete then
          begin
            if AddrMatches(IPCache[i].IP, AAddress) then
              exit(arLooking);
          end;
      end;

    i:=FindCacheIndex;
    IPCache[i].IP:=IPAddress(AAddress);
    IPCache[i].State:=asIncomplete;
    IPCache[i].TTL:=ARPCacheRetryTTL;

    SendRequest(i);

    exit(arLooking);
  end;

procedure ARPTick(ADelta: LongInt);
  var
    i: SizeInt;
  begin
    for i := 0 to ARPIPCacheSize-1 do
      begin
        case IPCache[i].State of
          asIncomplete,
          asComplete:
            begin
              dec(IPCache[i].TTL, ADelta);

              if IPCache[i].TTL<=0 then
                IPCache[i].State:=asUnused;
            end;
        end;
      end;
  end;

procedure ARPInput(var AIF: TNetif; APacket: PBuffer);
  var
    Header: TARPIPv4Header;
    MergeFlag: Boolean;
    i: SizeInt;
  begin
    APacket^.Read(Header, sizeof(Header), 0);

    if (Header.HLen<>HLEN_ETHER) or
       (BEtoN(Header.HType)<>HTYPE_ETHER) or
       (Header.PLen<>PLEN_IPv4) or
       (BEtoN(Header.PType)<>PTYPE_IPv4) then
      begin
        APacket^.DecRef;
        exit;
      end;

    MergeFlag:=false;
    for i := 0 to ARPIPCacheSize-1 do
      if IPCache[i].State in [asIncomplete,asComplete] then
        if AddrMatches(IPCache[i].IP, Header.SPA) then
          begin
            IPCache[i].Addr:=Header.SHA;
            IPCache[i].State:=asComplete;
            IPCache[i].TTL:=ARPCacheCompleteTTL;
            MergeFlag:=true;
          end;

    if AddrMatches(AIF.IPv4,Header.TPA) and
       (not AddrMatches(AIF.HWAddr,Header.THA)) then
      begin
        if not MergeFlag then
          begin
            i:=FindCacheIndex;

            IPCache[i].IP:=IPAddress(Header.SPA);
            IPCache[i].Addr:=Header.SHA;
            IPCache[i].State:=asComplete;
            IPCache[i].TTL:=ARPCacheCompleteTTL;
          end;

        if BEtoN(Header.Oper)=OPER_REQUEST then
          begin
            Header.Oper:=NtoBE(OPER_REPLY);

            Header.TPA:=Header.SPA;
            Header.THA:=Header.SHA;

            Header.SPA:=AIF.IPv4;
            Header.SHA:=AIF.HWAddr;

            APacket^.Write(Header, sizeof(Header), 0);

            EthOutput(AIF, Header.THA, ET_ARP, APacket);

            exit;
          end;
      end;

    APacket^.DecRef;
  end;

end.

