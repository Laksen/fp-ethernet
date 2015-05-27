unit fpethip;

interface

uses
  fpethbuf, fpethif,
  fpethtypes;

const
  IPPROTO_ICMP = $01;
  IPPROTO_IGMP = $02;
  IPPROTO_TCP = $06;
  IPPROTO_UDP = $11;
  IPPROTO_UDPLite = $88;

function IPOutput(var AIF: TNetif; AProto: word; const AIP: TIPAddress; APacket: PBuffer): TNetResult;
function IPOutput(AProto: word; const AIP: TIPAddress; APacket: PBuffer): TNetResult;

procedure IPv4Input(var AIF: TNetif; Packet: PBuffer);

implementation

uses
  fpetharp, fpethudp, fpethtcp, fpethicmp,
  fpethcfg;

var
  IDCount: word;

type
  TIPv4Header = packed record
    IHL,
    DSField: byte;
    TotalLength,
    ID,
    FragmentOffset: word;
    TTL,
    Protocol: byte;
    Checksum: word;
    Source,
    Dest: TIPv4Address;
  end;

  TIPOutFragment = record
    _IF: PNetif;
    ID: word;
    TTL: SmallInt;
    NextOffset: SizeInt;
    Dest: TIPAddress;
    Packet: PBuffer;
  end;

  TIPFragment = record
    _IF: PNetif;
    ID: word;
    TTL: SmallInt;
    NextOffset: SizeInt;
    Source, Dest: TIPAddress;
    Packet: PBuffer;
  end;

var
  Fragments: array[0..IPFragments-1] of TIPFragment;
  FragsToSend: array[0..IPOutputFragments-1] of TIPOutFragment;

function IPv4Reassemble(AIF: PNetif; AID, AFragOfs: Word; ASource, ADest: TIPv4Address; APacket: PBuffer): PBuffer;
  var
    Size: SizeInt;
    First, Last: Boolean;
    FragOfs, i, Idx: SizeInt;
  begin
    Idx:=-1;
    for i := 0 to IPFragments-1 do
      begin
        with Fragments[i] do
          if (_IF=AIF) and
             (ID=AID) and
             AddrMatches(Fragments[i].Dest, ADest) and
             AddrMatches(Fragments[i].Source, ASource) then
            begin
              Idx:=i;
              break;
            end;
      end;

    Size:=APacket^.TotalSize;
    FragOfs:=(AFragOfs and $1FFF)*8;
    First:=(FragOfs=0);
    Last:=(AFragOfs and $2000)=0;

    if Idx=-1 then
      begin
        if First then
          begin
            for i := 0 to IPFragments-1 do
              begin
                if (Fragments[i]._IF=nil) then
                  begin
                    Fragments[i]._IF:=AIF;
                    Fragments[i].ID:=AID;
                    Fragments[i].TTL:=IPFragmentTTL;
                    Fragments[i].NextOffset:=Size;
                    Fragments[i].Source:=IPAddress(ASource);
                    Fragments[i].Dest:=IPAddress(ADest);
                    Fragments[i].Packet:=APacket;

                    APacket:=nil;

                    break;
                  end;
              end;

            if assigned(APacket) then
              begin
                // We probably failed to find an empty slot
                APacket^.DecRef;
                APacket:=nil;
              end;
          end
        else
          begin
            // We probably missed the first fragment
            APacket^.DecRef;
            APacket:=nil;
          end;
      end
    else
      begin
        if Fragments[i].NextOffset=FragOfs then
          begin
            Fragments[i].Packet^.Concat(APacket);
            Fragments[i].NextOffset:=FragOfs+Size;

            if Last then
              begin
                APacket:=Fragments[i].Packet;

                Fragments[i]._IF:=nil;
              end
            else
              APacket:=nil;
          end
        else
          begin
            // We probably missed some fragment
            APacket^.DecRef;
            APacket:=nil;
          end;
      end;

    IPv4Reassemble:=APacket;
  end;

function SendFragment(var AIF: TNetif; AProto: word; const AHWAddr: THWAddress; const AIP: TIPAddress; APacket: PBuffer): TNetResult;
  begin
    APacket^.DecRef;
    exit(nrNotSupported);
  end;

function IPOutput(var AIF: TNetif; AProto: word; const AIP: TIPAddress; APacket: PBuffer): TNetResult;
  var
    HWAddr: THWAddress;
    Header: TIPv4Header;
  begin
    if AIP.AddrTyp=atIPv4 then
      begin
        HWAddr:=BroadcastAddr;
        if IsBroadcast(AIP.V4, AIF.SubMaskv4) or
           (ARPLookupIPv4(AIP.V4, HWAddr)=arSuccess) then
          begin
            if (APacket^.TotalSize+20)>AIF.MTU_Eth then
              begin
                if IPSupportFragmentationOutput then
                  begin
                    exit(SendFragment(AIF, AProto, HWAddr, AIP, APacket));
                  end
                else
                  begin
                    APacket^.DecRef;
                    exit(nrNotSupported);
                  end;
              end;

            Header.IHL:=$45;
            Header.Checksum:=0;
            Header.Dest:=AIP.V4;
            Header.Source:=AIF.IPv4;
            Header.DSField:=0;
            Header.FragmentOffset:=NtoBE($4000); // DF=1
            Header.ID:=NtoBE(IDCount); inc(IDCount);
            Header.TTL:=AIF.IPTTL;
            Header.Protocol:=AProto;
            Header.TotalLength:=NtoBE(word(20+APacket^.TotalSize));

            Header.Checksum:=(word(not CalcChecksum(Header, 20)));

            APacket:=APacket^.Expand(20,0);
            if assigned(APacket) then
              begin
                APacket^.Write(Header, sizeof(Header), 0);

                exit(EthOutput(AIF, HWAddr, ET_IPv4, APacket));
              end
            else
              exit(nrOutOfMem);
          end
        else
          begin
            APacket^.DecRef;
            exit(nrAddressLookup);
          end;
      end
    else
      begin
        writeln('IPv6');
        // IPv6 not supported
        APacket^.DecRef;
        exit(nrNotSupported);
      end;
  end;

function IPOutput(AProto: word; const AIP: TIPAddress; APacket: PBuffer): TNetResult;
  var
    aif: TNetif;
  begin
    if FindRoute(AIP, aif) then
      IPOutput:=IPOutput(AIF, AProto, AIP, APacket)
    else
      begin
        APacket^.DecRef;
        IPOutput:=nrNoRoute;
      end;
  end;

procedure IPv4Input(var AIF: TNetif; Packet: PBuffer);
  var
    Header: TIPv4Header;
    IHL,DataLength: SizeInt;
    FragOfs: Word;
    ChkSum: Word;
  begin
    Packet^.Read(Header, sizeof(TIPv4Header), 0);

    if ((Header.IHL shr 4)<>4) or
       (not (IsBroadcast(Header.Dest, AIF.SubMaskv4) or
             AddrMatches(Header.Dest, AIf.IPv4))) then
      begin
        //writeln('Bad IP version');
        Packet^.DecRef;
        exit;
      end;

    IHL:=(header.IHL and $F)*4;
    DataLength:=(BEtoN(header.TotalLength)-IHL);
    FragOfs:=BEtoN(header.FragmentOffset);

    ChkSum:=CalcChecksum(Packet, IHL);
    if (not word(ChkSum))<>0 then
      begin
        //writeln('Dropped due to checksum error: ', hexstr(chksum,4), ' = ', hexstr((not word(ChkSum)), 4));
        Packet^.DecRef;
        exit;
      end;

    Packet:=Packet^.Contract(IHL, Packet^.TotalSize-(IHL+DataLength));
    if not assigned(Packet) then
      exit;

    if ((FragOfs and $2000)<>0) or
       ((FragOfs and $1FFF)<>0) then
      begin
        if IPSupportFragmentation then
          Packet:=IPv4Reassemble(@AIF, BEtoN(Header.ID),FragOfs,Header.Source,Header.Dest,Packet)
        else
          begin
            Packet^.DecRef;
            Packet:=nil;
          end;
      end;

    if assigned(Packet) then
      case Header.Protocol of
        IPPROTO_ICMP: ICMPInput(AIF, IPAddress(Header.Source), Packet);
        IPPROTO_TCP: TCPInput(Packet);
        IPPROTO_UDP: UDPv4Input(AIF, Packet, Header.Source, Header.Dest);
      else
        writeln('Unknown protocol: ', hexstr(header.Protocol,2));
        Packet^.DecRef;
      end;
  end;

end.

