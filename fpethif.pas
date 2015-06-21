unit fpethif;

interface

uses
  fpethbuf, fpethtypes;

type
  TNetifFlag = (ifNoPadding);
  TNetifFlags = set of TNetifFlag;

  PNetif = ^TNetif;
  TNetif = record
    IPv4,
    SubMaskv4: TIPv4Address;

    IPv6: TIPv6Address;

    HWAddr: THWAddress;

    Data: pointer;

    // MTU for IP packets
    MTU_Eth: SmallInt;
    Flags: TNetifFlags;
    IPTTL: byte;

    Output: function(AData: pointer; APacket: PBuffer): TNetResult;
  end;

procedure AddIF(AIF: PNetif);

function FindRoute(const AIP: TIPAddress; out AIF: TNetif): Boolean;

// Called by stack, calls driver
function EthOutput(var AIF: TNetif; const ADst: THWAddress; ATyp: word; APacket: PBuffer): TNetResult;

// Called by Netif driver, reference should be 1, and driver should not decrease that after the call
procedure EthInput(var AIF: TNetif; APacket: PBuffer);

implementation

uses
  fpethip,
  fpetharp;

var
  IFs: PNetif = nil;

procedure AddIF(AIF: PNetif);
  begin
    IFs:=AIF;
  end;

function FindRoute(const AIP: TIPAddress; out AIF: TNetif): Boolean;
  var
    i: PNetif;
  begin
    i:=IFs;
    if assigned(i) then
      begin
        AIF:=i^;
        exit(true);
      end
    else
      exit(false);
  end;

function EthOutput(var AIF: TNetif; const ADst: THWAddress; ATyp: word; APacket: PBuffer): TNetResult;
  var
    Padding,PackSize: SizeInt;
  begin
    PackSize:=APacket^.TotalSize;

    if ifNoPadding in AIF.Flags then
      Padding:=0
    else
      begin
        // Min size is 48, and we don't add FCS
        Padding:=48+16-4-14-PackSize;
        if Padding<0 then Padding:=0;
      end;

    APacket:=APacket^.Expand(14,Padding);

    if not assigned(APacket) then
      exit(nrOutOfMem);

    ATyp:=NtoBE(ATyp);

    // Write ethernet frame
    APacket^.Write(ADst[0], sizeof(THWAddress), 0);
    APacket^.Write(AIF.HWAddr[0], sizeof(THWAddress), 6);
    APacket^.Write(ATyp, 2, 12);

    if Padding<>0 then
      APacket^.WriteZero(Padding, PackSize+14);

    // Write to netif
    exit(AIF.Output(AIF.Data, APacket));
  end;

procedure EthInput(var AIF: TNetif; APacket: PBuffer);
  var
    Dst,src: THWAddress;
    Typ: word;
  begin
    // Check dst address
    APacket^.Read(Dst, SizeOf(THWAddress), 0);

    if (not AddrMatches(Dst, AIF.HWAddr)) and
       (not IsBroadcast(Dst)) then
      begin
        APacket^.DecRef;
        exit;
      end;

    APacket^.Read(Typ, 2, 12);

    APacket:=APacket^.Contract(14, 0);

    if assigned(APacket) then
      case BEtoN(Typ) of
        ET_IPv4: IPv4Input(AIF, APacket);
        ET_ARP: ARPInput(AIF, APacket);
      else
        writeln('Unknown ethernet type: ', hexstr(BEtoN(typ),4));
        APacket^.DecRef;
      end;
  end;

end.

