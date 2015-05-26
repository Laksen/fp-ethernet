unit fpethtypes;

interface

uses
  fpethbuf;

const
  ET_ARP  = $0806;
  ET_IPv4 = $0800;
  ET_IPv6 = $86DD;

type
  TNetResult = (nrOk, nrAddressLookup, nrOutOfMem, nrQueueFull, nrNoRoute, nrNotSupported, nrPortOccupied, nrNotConnected);

  THWAddress = array[0..5] of byte;

  PIPv4Address = ^TIPv4Address;
  TIPv4Address = record
    case integer of
      0: (val: longword);
      1: (bytes: array[0..3] of byte);
  end;

  PIPv6Address = ^TIPv6Address;
  TIPv6Address = record
    case integer of
      0: (bytes: array[0..15] of byte);
  end;

  TIPAddressType = (atIPv4, atIPv6);

  PIPAddress = ^TIPAddress;
  TIPAddress = record
    AddrTyp: TIPAddressType;
    case TIPAddressType of
      atIPv4: (V4: TIPv4Address);
      atIPv6: (V6: TIPv6Address);
  end;

const
  IPv4_AnyAddr: TIPv4Address = (val: $FFFFFFFF);
  BroadcastAddr: THWAddress = ($FF,$FF,$FF,$FF,$FF,$FF);

function HWAddress(a,b,c,d,e,f: byte): THWAddress;
function IPv4Address(a,b,c,d: byte): TIPv4Address;
function IPAddress(const IP: TIPv4Address): TIPAddress;

function AddrMatches(const A: TIPAddress; const B: TIPv4Address): boolean;
function AddrMatches(const A: TIPAddress; const B: TIPv6Address): boolean;
function AddrMatches(const A, B: TIPv4Address): boolean;
function AddrMatches(const A, B: TIPv6Address): boolean;

function AddrMatches(const A,B: THWAddress): boolean;
function IsBroadcast(const A: THWAddress): boolean;

function IsBroadcast(const A, ASubNet: TIPv4Address): boolean;

function GetStr(const AAddr: THWAddress): string;
function GetStr(const AAddr: TIPv4Address): string;

function CalcCRC32(ACRC: longword; AData: PByte; ACount: SizeInt): longword;

function CalcChecksum(var AData; ACount: SizeInt): word;
function CalcChecksum(APacket: PBuffer; ACount: SizeInt): word;
function CalcUDPIPv4Checksum(AChkSum: Word; const ASource, ADest: TIPv4Address; ALen: Word): word;

procedure DoTick();

implementation

uses
  fpetharp,fpethtcp,fpethudp,fpethip,
  fpethcfg;

function HWAddress(a, b, c, d, e, f: byte): THWAddress;
  begin
    HWAddress[0]:=a;
    HWAddress[1]:=b;
    HWAddress[2]:=c;
    HWAddress[3]:=d;
    HWAddress[4]:=e;
    HWAddress[5]:=f;
  end;

function IPv4Address(a, b, c, d: byte): TIPv4Address;
  begin
    IPv4Address.bytes[0]:=a;
    IPv4Address.bytes[1]:=b;
    IPv4Address.bytes[2]:=c;
    IPv4Address.bytes[3]:=d;
  end;

function IPAddress(const IP: TIPv4Address): TIPAddress;
  begin
    result.AddrTyp:=atIPv4;
    result.V4:=IP;
  end;

function AddrMatches(const A: TIPAddress; const B: TIPv4Address): boolean;
  begin
    if A.AddrTyp<>atIPv4 then exit(false);
    AddrMatches:=a.V4.val=b.val;
  end;

function AddrMatches(const A: TIPAddress; const B: TIPv6Address): boolean;
  begin
    if A.AddrTyp<>atIPv6 then exit(false);
    AddrMatches:=CompareByte(a.V6.bytes[0], b.bytes[0], 16)=0;
  end;

function AddrMatches(const A, B: TIPv4Address): boolean;
  begin
    AddrMatches:=a.val=b.val;
  end;

function AddrMatches(const A, B: TIPv6Address): boolean;
  begin
    AddrMatches:=CompareByte(a.bytes[0], b.bytes[0], 16)=0;
  end;

function AddrMatches(const A, B: THWAddress): boolean;
  begin
    AddrMatches:=CompareByte(a[0], b[0], 6)=0;
  end;

function IsBroadcast(const A: THWAddress): boolean;
  begin
    IsBroadcast:=(a[0] and $01)<>0;
  end;

function IsBroadcast(const A, ASubNet: TIPv4Address): boolean;
  var
    SubInv: LongWord;
  begin
    SubInv:=not ASubNet.val;

    IsBroadcast:=(SubInv and a.val)=SubInv;
  end;

function GetStr(const AAddr: THWAddress): string;
  begin
    GetStr:=hexStr(AAddr[0],2)+'-'+
            hexStr(AAddr[1],2)+'-'+
            hexStr(AAddr[2],2)+'-'+
            hexStr(AAddr[3],2)+'-'+
            hexStr(AAddr[4],2)+'-'+
            hexStr(AAddr[5],2);
  end;

function GetStr(const AAddr: TIPv4Address): string;
  begin
    WriteStr(GetStr, AAddr.bytes[0],'.',AAddr.bytes[1],'.',AAddr.bytes[2],'.',AAddr.bytes[3]);
  end;

{ ========================================================================
  Table of CRC-32's of all single-byte values (made by make_crc32_table) }

{local}
const
  crc32_table : array[Byte] of cardinal = (
  $00000000, $77073096, $ee0e612c, $990951ba, $076dc419,
  $706af48f, $e963a535, $9e6495a3, $0edb8832, $79dcb8a4,
  $e0d5e91e, $97d2d988, $09b64c2b, $7eb17cbd, $e7b82d07,
  $90bf1d91, $1db71064, $6ab020f2, $f3b97148, $84be41de,
  $1adad47d, $6ddde4eb, $f4d4b551, $83d385c7, $136c9856,
  $646ba8c0, $fd62f97a, $8a65c9ec, $14015c4f, $63066cd9,
  $fa0f3d63, $8d080df5, $3b6e20c8, $4c69105e, $d56041e4,
  $a2677172, $3c03e4d1, $4b04d447, $d20d85fd, $a50ab56b,
  $35b5a8fa, $42b2986c, $dbbbc9d6, $acbcf940, $32d86ce3,
  $45df5c75, $dcd60dcf, $abd13d59, $26d930ac, $51de003a,
  $c8d75180, $bfd06116, $21b4f4b5, $56b3c423, $cfba9599,
  $b8bda50f, $2802b89e, $5f058808, $c60cd9b2, $b10be924,
  $2f6f7c87, $58684c11, $c1611dab, $b6662d3d, $76dc4190,
  $01db7106, $98d220bc, $efd5102a, $71b18589, $06b6b51f,
  $9fbfe4a5, $e8b8d433, $7807c9a2, $0f00f934, $9609a88e,
  $e10e9818, $7f6a0dbb, $086d3d2d, $91646c97, $e6635c01,
  $6b6b51f4, $1c6c6162, $856530d8, $f262004e, $6c0695ed,
  $1b01a57b, $8208f4c1, $f50fc457, $65b0d9c6, $12b7e950,
  $8bbeb8ea, $fcb9887c, $62dd1ddf, $15da2d49, $8cd37cf3,
  $fbd44c65, $4db26158, $3ab551ce, $a3bc0074, $d4bb30e2,
  $4adfa541, $3dd895d7, $a4d1c46d, $d3d6f4fb, $4369e96a,
  $346ed9fc, $ad678846, $da60b8d0, $44042d73, $33031de5,
  $aa0a4c5f, $dd0d7cc9, $5005713c, $270241aa, $be0b1010,
  $c90c2086, $5768b525, $206f85b3, $b966d409, $ce61e49f,
  $5edef90e, $29d9c998, $b0d09822, $c7d7a8b4, $59b33d17,
  $2eb40d81, $b7bd5c3b, $c0ba6cad, $edb88320, $9abfb3b6,
  $03b6e20c, $74b1d29a, $ead54739, $9dd277af, $04db2615,
  $73dc1683, $e3630b12, $94643b84, $0d6d6a3e, $7a6a5aa8,
  $e40ecf0b, $9309ff9d, $0a00ae27, $7d079eb1, $f00f9344,
  $8708a3d2, $1e01f268, $6906c2fe, $f762575d, $806567cb,
  $196c3671, $6e6b06e7, $fed41b76, $89d32be0, $10da7a5a,
  $67dd4acc, $f9b9df6f, $8ebeeff9, $17b7be43, $60b08ed5,
  $d6d6a3e8, $a1d1937e, $38d8c2c4, $4fdff252, $d1bb67f1,
  $a6bc5767, $3fb506dd, $48b2364b, $d80d2bda, $af0a1b4c,
  $36034af6, $41047a60, $df60efc3, $a867df55, $316e8eef,
  $4669be79, $cb61b38c, $bc66831a, $256fd2a0, $5268e236,
  $cc0c7795, $bb0b4703, $220216b9, $5505262f, $c5ba3bbe,
  $b2bd0b28, $2bb45a92, $5cb36a04, $c2d7ffa7, $b5d0cf31,
  $2cd99e8b, $5bdeae1d, $9b64c2b0, $ec63f226, $756aa39c,
  $026d930a, $9c0906a9, $eb0e363f, $72076785, $05005713,
  $95bf4a82, $e2b87a14, $7bb12bae, $0cb61b38, $92d28e9b,
  $e5d5be0d, $7cdcefb7, $0bdbdf21, $86d3d2d4, $f1d4e242,
  $68ddb3f8, $1fda836e, $81be16cd, $f6b9265b, $6fb077e1,
  $18b74777, $88085ae6, $ff0f6a70, $66063bca, $11010b5c,
  $8f659eff, $f862ae69, $616bffd3, $166ccf45, $a00ae278,
  $d70dd2ee, $4e048354, $3903b3c2, $a7672661, $d06016f7,
  $4969474d, $3e6e77db, $aed16a4a, $d9d65adc, $40df0b66,
  $37d83bf0, $a9bcae53, $debb9ec5, $47b2cf7f, $30b5ffe9,
  $bdbdf21c, $cabac28a, $53b39330, $24b4a3a6, $bad03605,
  $cdd70693, $54de5729, $23d967bf, $b3667a2e, $c4614ab8,
  $5d681b02, $2a6f2b94, $b40bbe37, $c30c8ea1, $5a05df1b,
  $2d02ef8d);

function CalcCRC32(ACRC: longword; AData: PByte; ACount: SizeInt): longword;
  begin
    if AData = nil then
      exit(0);

{$IFDEF DYNAMIC_CRC_TABLE}
    if crc32_table_empty then
      make_crc32_table;
{$ENDIF}

    ACRC := ACRC xor $FFFFFFFF;
    while (ACount >= 8) do
      begin
        ACRC := crc32_table[(ACRC xor AData^) and $ff] xor (ACRC shr 8);
        inc(AData);
        ACRC := crc32_table[(ACRC xor AData^) and $ff] xor (ACRC shr 8);
        inc(AData);
        ACRC := crc32_table[(ACRC xor AData^) and $ff] xor (ACRC shr 8);
        inc(AData);
        ACRC := crc32_table[(ACRC xor AData^) and $ff] xor (ACRC shr 8);
        inc(AData);
        ACRC := crc32_table[(ACRC xor AData^) and $ff] xor (ACRC shr 8);
        inc(AData);
        ACRC := crc32_table[(ACRC xor AData^) and $ff] xor (ACRC shr 8);
        inc(AData);
        ACRC := crc32_table[(ACRC xor AData^) and $ff] xor (ACRC shr 8);
        inc(AData);
        ACRC := crc32_table[(ACRC xor AData^) and $ff] xor (ACRC shr 8);
        inc(AData);
        dec(ACount, 8);
      end;

    while (ACount > 0) do
      begin
        ACRC := crc32_table[(ACRC xor AData^) and $ff] xor (ACRC shr 8);
        inc(AData);
        dec(ACount);
      end;

    result := ACRC xor $FFFFFFFF;
  end;

function CalcChecksum(var AData; ACount: SizeInt): word;
  var
    pw: PWord;
    sum: longword;
  begin
    pw:=@AData;

    sum:=0;
    while ACount>1 do
      begin
        sum:=sum+pw^;
        inc(pw);
        dec(ACount,2);
      end;

    if ACount>0 then
      sum:=sum+(pbyte(pw)^ shl 8);

    Sum:=(Sum and $FFFF)+(Sum shr 16);
    Result:=(Sum and $FFFF)+(Sum shr 16);
  end;

function CalcChecksum(APacket: PBuffer; ACount: SizeInt): word;
  var
    OddByte: Boolean;
    LastByte: byte;

    Sum: longword;
    pb: PByte;
    Cnt: SizeInt;
  begin
    OddByte:=false;
    LastByte:=0;

    Sum:=0;

    while assigned(APacket) and
          (ACount>0) do
      begin
        pb:=@APacket^.Data[APacket^.Offset];
        Cnt:=APacket^.Size;
        if Cnt>ACount then
          Cnt:=ACount;

        Dec(ACount,Cnt);

        if OddByte and
           (Cnt>0) then
          begin
            Sum:=Sum+(BEtoN(word((pb^ shl 8) or LastByte)));
            inc(pb);
            dec(Cnt);
            OddByte:=false;
          end;

        while Cnt>=2 do
          begin
            Sum:=Sum+BEtoN(pword(pb)^);
            inc(pb,2);
            dec(Cnt,2);
          end;

        if Cnt>0 then
          begin
            OddByte:=true;
            LastByte:=pb^;
          end;

        APacket:=APacket^.Next;
      end;

    if OddByte then
      Sum:=Sum+LastByte;

    Sum:=(Sum and $FFFF)+(Sum shr 16);
    Result:=(Sum and $FFFF)+(Sum shr 16);
  end;

function CalcUDPIPv4Checksum(AChkSum: Word; const ASource, ADest: TIPv4Address; ALen: Word): word;
  var
    sum, tmp: LongWord;
  begin
    tmp:=BEtoN(ASource.val);
    sum:=(tmp and $FFFF)+(tmp shr 16);
    tmp:=BEtoN(ADest.val);
    sum:=sum+(tmp and $FFFF)+(tmp shr 16);
    sum:=sum+$11; // Protocol
    sum:=sum+ALen;
    sum:=sum+AChkSum;

    Sum:=(Sum and $FFFF)+(Sum shr 16);
    Result:=(Sum and $FFFF)+(Sum shr 16);
  end;

var
  OldTick: longword = 0;
  FirstTick: Boolean = true;

procedure DoTick();
  var
    NewTick,Delta: LongWord;
  begin
    if FirstTick then
      begin
        OldTick:=GetMSTick;
        FirstTick:=false;
      end
    else
      begin
        NewTick:=GetMSTick;
        Delta:=NewTick-OldTick;
        OldTick:=NewTick;

        ARPTick(Delta);
      end;
  end;

end.

