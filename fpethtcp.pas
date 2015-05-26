unit fpethtcp;

interface

uses
  fpethbuf;

procedure TCPInput(APacket: PBuffer);

implementation

procedure TCPInput(APacket: PBuffer);
  begin
    writeln('TCP packet');
    APacket^.DecRef;
  end;

end.

