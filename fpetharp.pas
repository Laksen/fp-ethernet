unit fpetharp;

interface

uses
  fpethif, fpethtypes, fpethbuf;

type
  TArpResult = (arSuccess, arLooking);

procedure ARPSendGratuitous(var AIF: TNetif);

function ARPLookup(const AAddress: TIPAddress; var AHWAddress: THWAddress): TArpResult;

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
    _IF: TNetif;
    wr: TBufferWriter;
  begin
    IPCache[AIndex].TTL:=ARPCacheRetryTTL;

    // TODO: implement IPv6
    if IPCache[AIndex].IP.AddrTyp<>atIPv4 then
      exit;

    if FindRoute(IPCache[AIndex].IP, _IF) then
      begin
        Pack:=AllocateBuffer(sizeof(TARPIPv4Header), plLink);
        if assigned(Pack) then
          begin
            wr:=Pack^.GetWriter;

            wr.WriteWord(NtoBE(word(HTYPE_ETHER)));
            wr.WriteWord(NtoBE(word(PTYPE_IPv4)));
            wr.WriteByte(HLEN_ETHER);
            wr.WriteByte(PLEN_IPv4);

            wr.WriteWord(NtoBE(word(OPER_REQUEST)));

            wr.Write(_IF.HWAddr, SizeOf(THWAddress));
            wr.Write(_IF.IPv4, SizeOf(TIPv4Address));
            wr.Write(BroadcastAddr, SizeOf(THWAddress));
            wr.Write(IPCache[AIndex].IP.V4, SizeOf(TIPv4Address));

            EthOutput(_IF, BroadcastAddr, ET_ARP, Pack);
          end;
      end;
  end;

procedure ARPSendGratuitous(var AIF: TNetif);
  var
    Pack: PBuffer;
    wr: TBufferWriter;
  begin
    Pack:=AllocateBuffer(sizeof(TARPIPv4Header), plLink);
    if assigned(Pack) then
      begin
        wr:=Pack^.GetWriter;

        wr.WriteWord(NtoBE(word(HTYPE_ETHER)));
        wr.WriteWord(NtoBE(word(PTYPE_IPv4)));
        wr.WriteByte(HLEN_ETHER);
        wr.WriteByte(PLEN_IPv4);

        wr.WriteWord(NtoBE(word(OPER_REQUEST)));

        wr.Write(AIF.HWAddr, SizeOf(THWAddress));
        wr.Write(AIF.IPv4, SizeOf(TIPv4Address));
        wr.Write(BroadcastAddr, SizeOf(THWAddress));
        wr.Write(AIF.IPv4, SizeOf(TIPv4Address));

        EthOutput(AIF, BroadcastAddr, ET_ARP, Pack);
      end;
  end;

function ARPLookup(const AAddress: TIPAddress; var AHWAddress: THWAddress): TArpResult;
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
    IPCache[i].IP:=AAddress;
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
    MergeFlag: Boolean;
    i: SizeInt;
    rd: TBufferWriter;
    wr: TBufferWriter;

    htyp,ptyp: Word;
    hlen,plen: Byte;
    oper: word;
    spa,tpa: TIPv4Address;
    sha,tha: THWAddress;
  begin
    rd:=APacket^.GetWriter;

    repeat
      htyp:=BEtoN(rd.ReadWord);
      if htyp<>HTYPE_ETHER then
        break;

      ptyp:=BEtoN(rd.ReadWord);
      if ptyp<>PTYPE_IPv4 then
        break;

      hlen:=rd.ReadByte;
      if hlen<>HLEN_ETHER then
        break;

      plen:=rd.ReadByte;
      if plen<>PLEN_IPv4 then
        break;

      wr:=rd;
      oper:=BEtoN(rd.ReadWord);
      rd.Read(sha, sizeof(THWAddress));
      rd.Read(spa, sizeof(TIPv4Address));
      rd.Read(tha, sizeof(THWAddress));
      rd.Read(tpa, sizeof(TIPv4Address));

      MergeFlag:=false;
      for i := 0 to ARPIPCacheSize-1 do
        if IPCache[i].State in [asIncomplete,asComplete] then
          if AddrMatches(IPCache[i].IP, SPA) then
            begin
              IPCache[i].Addr:=SHA;
              IPCache[i].State:=asComplete;
              IPCache[i].TTL:=ARPCacheCompleteTTL;
              MergeFlag:=true;
            end;

      if AddrMatches(AIF.IPv4,TPA) and
         (not AddrMatches(AIF.HWAddr,THA)) then
        begin
          if not MergeFlag then
            begin
              i:=FindCacheIndex;

              IPCache[i].IP:=IPAddress(SPA);
              IPCache[i].Addr:=SHA;
              IPCache[i].State:=asComplete;
              IPCache[i].TTL:=ARPCacheCompleteTTL;
            end;

          if Oper=OPER_REQUEST then
            begin
              wr.WriteWord(NtoBE(OPER_REPLY));

              wr.Write(AIF.HWAddr, sizeof(THWAddress));
              wr.Write(AIF.IPv4, sizeof(TIPv4Address));
              wr.Write(SHA, sizeof(THWAddress));
              wr.Write(SPA, sizeof(TIPv4Address));

              EthOutput(AIF, SHA, ET_ARP, APacket);

              exit;
            end;
        end;
    until true;

    APacket^.DecRef;
  end;

end.

