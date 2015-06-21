unit fpethcfg;

interface

{ Global }
const
  IsConcurrent = true;

{ Buffers }
const
  BufferSize = 256*4;
  BufferCount = 32*4;

  DescriptorCount = 48;

{ ARP }
const
  ARPIPCacheSize = 8;

  ARPCacheRestartTTLOnUse = true;
  ARPCacheCompleteTTL = 20*60*1000;
  ARPCacheRetryTTL = 1000;

{ IP }
const
  IPSupportFragmentation = true;
  IPSupportFragmentationOutput = false;

  IPFragments = 4;
  IPFragmentTTL = 1000;

  IPOutputFragments = 8;
  IPOutputFragmentTTL = 1000;

{ DHCP }
const
  DHCPClientCount = 1;

  DHCPInitRetryTime = 10*1000;

  DHCPRequestTimeout = 2*1000;
  DHCPRequestRetryTimeout = 1*1000;

{ TCP }
const
  TCPMSS = 1460;

  TCPMaxReceiveWindow = 16*TCPMSS;

// Return a millisecond time. May overflow
function GetMSTick: longword;

function GetRandom32(AData: pointer): longword;

implementation

uses
  unix;

function GetTickCount64: QWord;
var
  tp: TTimeVal;
  {$IFDEF HAVECLOCKGETTIME}
  ts: TTimeSpec;
  {$ENDIF}

begin
 {$IFDEF HAVECLOCKGETTIME}
   if clock_gettime(CLOCK_MONOTONIC, @ts)=0 then
     begin
     Result := (Int64(ts.tv_sec) * 1000) + (ts.tv_nsec div 1000000);
     exit;
     end;
 {$ENDIF}
  fpgettimeofday(@tp, nil);
  Result := (Int64(tp.tv_sec) * 1000) + (tp.tv_usec div 1000);
end;

function GetMSTick: longword;
  begin
    result:=GetTickCount64;
  end;

function GetRandom32(AData: pointer): longword;
  begin
    result:=Random(MaxInt);
  end;

end.

