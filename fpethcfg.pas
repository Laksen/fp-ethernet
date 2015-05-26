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

// Return a millisecond time. May overflow
function GetMSTick: longword;

implementation

uses
  sysutils;

function GetMSTick: longword;
  begin
    result:=GetTickCount;
  end;

end.

