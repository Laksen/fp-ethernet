unit fpethicmp;

interface

uses
  fpethbuf, fpethif,
  fpethtypes;

procedure ICMPInput(var AIF: TNetif; ASource: TIPAddress; APacket: PBuffer);

implementation

uses
  fpethip;

type
  TICMPHeader = packed record
    _Type,
    Code: byte;
    Checksum: word;
    Data: longword;
  end;

const
  TYPE_ECHO_REQUEST = 8;
  TYPE_ECHO_REPLY = 0;

function RecalcChecksum(ASum: word; AOld, AModification: word): word;
  var
    Sum: LongWord;
  begin
    Sum:=ASum+word(not AOld)+AModification;

    Sum:=(Sum and $FFFF)+(Sum shr 16);
    Result:=(Sum and $FFFF)+(Sum shr 16);
  end;

procedure ICMPInput(var AIF: TNetif; ASource: TIPAddress; APacket: PBuffer);
  var
    Header: TICMPHeader;
  begin
    APacket^.Read(Header, Sizeof(Header), 0);

    if Header._Type=TYPE_ECHO_REQUEST then
      begin
        Header._Type:=TYPE_ECHO_REPLY;
        Header.Checksum:=NtoBE(word(not RecalcChecksum(BEtoN(not Header.Checksum), TYPE_ECHO_REQUEST shl 8, TYPE_ECHO_REPLY shl 8)));

        APacket^.Write(header, sizeof(header), 0);

        writeln('Got ping');

        IPOutput(AIF, IPPROTO_ICMP, ASource, APacket);
      end
    else
      APacket^.DecRef;
  end;

end.

