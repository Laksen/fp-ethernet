unit fpethbuf;

interface

{$modeswitch AdvancedRecords}

type
  TProtocolLayer = (plPhy, plLink, plNetwork, plApplication);

  TBufferFlag = (bfWritten, bfOwnsMem);
  TBufferFlags = set of TBufferFlag;

  PBuffer = ^TBuffer;
  TBuffer = record
    Data: PByte;
    DataSize: SizeInt;

    Offset, Size: SizeInt;

    Next: PBuffer;

    RefCnt: longint;

    Flags: TBufferFlags;

    procedure Free;

    function AddRef: longint;
    procedure DecRef;

    function TotalSize: SizeInt;

    procedure Concat(ABuffer: PBuffer);

    function Clone: PBuffer;
    function MakeUnique: PBuffer;

    function Expand(AHeader, ATail: SizeInt): PBuffer;

    function Contract(AHeader, ATail: SizeInt): PBuffer;

    function Write(const ABuf; ACount, AOffset: SizeInt): SizeInt;
    function WriteZero(ACount, AOffset: SizeInt): SizeInt;
    function Read(var ABuf; ACount, AOffset: SizeInt): SizeInt;
  private
    function ExpandHeader(AHeader: SizeInt): PBuffer;
    function ExpandTail(ATail: SizeInt): PBuffer;

    function ContractHeader(AHeader: SizeInt): PBuffer;
    function ContractTail(ATail: SizeInt): PBuffer;
  end;

function AllocateWindow(ABuffer: PBuffer): PBuffer;
function AllocateBuffer(ASize: SizeInt; ALayerHint: TProtocolLayer = plApplication): PBuffer;
function AllocateStaticBuffer(AData: Pointer; ASize: SizeInt): PBuffer;

implementation

uses fpethcfg;

type
  PDataBuffer = ^TDataBuffer;
  TDataBuffer = record
    case integer of
      0: (Mem: array[0..BufferSize-1] of byte);
      1: (Next: PDataBuffer);
  end;

var
  BufferStorage: array[0..BufferCount-1] of TDataBuffer;
  FreeBuffers: PDataBuffer;

  Descriptors: array[0..DescriptorCount-1] of TBuffer;
  FreeDescriptors: PBuffer;

function GetDescriptor: PBuffer;
  var
    Desc, Next: PBuffer;
  begin
    if IsConcurrent then
      begin
        Desc:=FreeDescriptors;
        while assigned(Desc) do
          begin
            Next:=Desc^.Next;
            if InterlockedCompareExchange(FreeDescriptors, Next, Desc)=Desc then
              break;
            Desc:=FreeDescriptors;
          end;
      end
    else
      begin
        Desc:=FreeDescriptors;
        if assigned(Desc) then
          FreeDescriptors:=Desc^.Next;
      end;

    GetDescriptor:=Desc;
  end;

function GetBuffer: PDataBuffer;
  var
    Buf, Next: PDataBuffer;
  begin
    if IsConcurrent then
      begin
        Buf:=FreeBuffers;
        while assigned(Buf) do
          begin
            Next:=Buf^.Next;
            if InterlockedCompareExchange(FreeBuffers, Next, Buf)=Buf then
              break;
            Buf:=FreeBuffers;
          end;
      end
    else
      begin
        Buf:=FreeBuffers;
        if assigned(Buf) then
          FreeBuffers:=Buf^.Next;
      end;

    GetBuffer:=Buf;
  end;

procedure FreeDescriptor(Desc: PBuffer);
  begin
    if IsConcurrent then
      begin
        repeat
          Desc^.Next:=FreeDescriptors;
        until InterlockedCompareExchange(FreeDescriptors, Desc, Desc^.Next)=Desc^.Next;
      end
    else
      begin
        Desc^.Next:=FreeDescriptors;
        FreeDescriptors:=Desc;
      end;
  end;

procedure FreeBuffer(Buf: PDataBuffer);
  begin
    if IsConcurrent then
      begin
        repeat
          Buf^.Next:=FreeBuffers;
        until InterlockedCompareExchange(FreeBuffers, Buf, Buf^.Next)=Buf^.Next;
      end
    else
      begin
        Buf^.Next:=FreeBuffers;
        FreeBuffers:=Buf;
      end;
  end;

function AllocateSingleBuffer(AllocBuf: boolean): PBuffer;
  var
    Desc: PBuffer;
    Buf: PDataBuffer;
  begin
    Desc:=GetDescriptor;
    if Desc=nil then
      exit(nil);

    if AllocBuf then
      begin
        Buf:=GetBuffer;
        if not assigned(Buf) then
          begin
            FreeDescriptor(Desc);
            exit(nil);
          end;

        Desc^.Data:=@Buf^.Mem[0];
        Desc^.DataSize:=BufferSize;
        Desc^.Flags:=[bfOwnsMem];
      end
    else
      begin
        Desc^.Data:=Nil;
        Desc^.DataSize:=0;
        Desc^.Flags:=[];
      end;

    Desc^.Offset:=0;
    Desc^.Size:=0;
    Desc^.Next:=nil;
    Desc^.RefCnt:=1;
    Desc^.Flags:=[bfOwnsMem];

    AllocateSingleBuffer:=Desc;
  end;

const
  ExtraHeader: array[TProtocolLayer] of byte = (0,
                                                14,
                                                14+40,
                                                14+40+16);
  ExtraTail: array[TProtocolLayer] of byte = (0,
                                              4,
                                              4+0,
                                              4+0+0);

function AllocateWindow(ABuffer: PBuffer): PBuffer;
  var
    p: PBuffer;
    i, Cnt: sizeint;
    newbuf: PBuffer;
  begin
    Cnt:=0;

    p:=ABuffer;
    while assigned(p) do
      begin
        inc(cnt);
        p:=p^.Next;
      end;

    p:=AllocateSingleBuffer(false);
    AllocateWindow:=p;

    if not assigned(p) then
      exit;

    repeat
      p^.Data:=ABuffer^.Data;
      p^.DataSize:=ABuffer^.DataSize;

      p^.Offset:=ABuffer^.Offset;
      p^.Size:=ABuffer^.Size;

      dec(cnt);

      if Cnt>0 then
        begin
          newbuf:=AllocateSingleBuffer(false);

          if not assigned(newbuf) then
            begin
              AllocateWindow^.Free;
              exit(nil);
            end;

          p^.Next:=newbuf;
          p:=newbuf;

          ABuffer:=ABuffer^.Next;
        end
      else
        break;
    until false;
  end;

function AllocateBuffer(ASize: SizeInt; ALayerHint: TProtocolLayer = plApplication): PBuffer;
  var
    res,n,tmp: PBuffer;
    AllocSize,HeaderSize,TailSize: SizeInt;
  begin
    HeaderSize:=ExtraHeader[ALayerHint];
    TailSize:=ExtraTail[ALayerHint];

    if HeaderSize>=BufferSize then
      HeaderSize:=0;

    AllocSize:=ASize+HeaderSize+TailSize;

    if AllocSize<=BufferSize then
      begin
        res:=AllocateSingleBuffer(true);

        if assigned(res) then
          begin
            res^.Size:=ASize;
            res^.Offset:=res^.DataSize-(ASize+TailSize);
          end;
      end
    else
      begin
        res:=AllocateSingleBuffer(true);
        if assigned(res) then
          begin
            res^.Size:=BufferSize-HeaderSize;
            res^.Offset:=HeaderSize;
            n:=res;
            dec(AllocSize,BufferSize);

            while (AllocSize>0) and
                  assigned(res) do
              begin
                tmp:=AllocateSingleBuffer(true);

                if assigned(tmp) then
                  begin
                    if AllocSize>BufferSize then
                      tmp^.Size:=BufferSize
                    else
                      tmp^.size:=AllocSize;

                    dec(AllocSize, BufferSize);
                    n^.next:=tmp;
                    n:=tmp;
                  end
                else
                  begin
                    res^.free;
                    res:=nil;
                  end;
              end;
          end;
      end;
    AllocateBuffer:=res;
  end;

function AllocateStaticBuffer(AData: Pointer; ASize: SizeInt): PBuffer;
  var
    Desc: PBuffer;
  begin
    Desc:=GetDescriptor;

    if assigned(Desc) then
      begin
        Desc^.Data:=AData;
        Desc^.DataSize:=ASize;

        Desc^.Offset:=0;
        Desc^.Size:=ASize;
        Desc^.Next:=nil;
        Desc^.RefCnt:=1;
        Desc^.Flags:=[bfWritten];
      end;

    AllocateStaticBuffer:=Desc;
  end;

procedure TBuffer.Free;
  var
    cur, N: PBuffer;
  begin
    cur:=@Self;

    while assigned(cur) do
      begin
        N:=cur^.Next;

        if bfOwnsMem in cur^.Flags then
          FreeBuffer(PDataBuffer(cur^.Data));

        FreeDescriptor(cur);

        cur:=N;
      end;
  end;

function TBuffer.AddRef: longint;
  begin
    if IsConcurrent then
      AddRef:=InterLockedIncrement(RefCnt)
    else
      begin
        inc(RefCnt);
        AddRef:=RefCnt;
      end;
  end;

procedure TBuffer.DecRef;
  var
    OldCnt: LongInt;
    p: PBuffer;
  begin
    if IsConcurrent then
      OldCnt:=InterLockedDecrement(RefCnt)
    else
      begin
        OldCnt:=RefCnt;
        Inc(RefCnt);
      end;

    if OldCnt < 1 then
      Free;
  end;

function TBuffer.TotalSize: SizeInt;
  var
    n: PBuffer;
  begin
    TotalSize:=Size;

    n:=Next;
    while Assigned(n) do
      begin
        inc(TotalSize, n^.Size);
        n:=n^.Next;
      end;
  end;

procedure TBuffer.Concat(ABuffer: PBuffer);
  var
    p: PBuffer;
  begin
    p:=self.MakeUnique;

    while assigned(p^.Next) do
      p:=p^.next;

    p^.next:=ABuffer;
  end;

function TBuffer.Clone: PBuffer;
  var
    sz,
    os, od,
    ms, md: SizeInt;
    pd,ps,res: PBuffer;
  begin
    sz:=TotalSize;
    res:=AllocateBuffer(sz, plPhy);

    ps:=@self;
    pd:=res;

    os:=0;
    od:=0;

    while assigned(ps) and
          assigned(pd) do
      begin
        ms:=ps^.Size-os;
        md:=pd^.Size-od;

        if ms=md then
          begin
            move(ps^.Data[ps^.Offset+os], pd^.Data[pd^.Offset+od], ms);

            ps:=ps^.Next; os:=0;
            pd:=pd^.Next; od:=0;
          end
        else if ms<md then
          begin
            move(ps^.Data[ps^.Offset+os], pd^.Data[pd^.Offset+od], ms);

            ps:=ps^.next; os:=0;
            inc(od, ms);
          end
        else
          begin
            move(ps^.Data[ps^.Offset+os], pd^.Data[pd^.Offset+od], md);

            inc(os, md);
            pd:=pd^.next; od:=0;
          end;
      end;

    Clone:=res;
  end;

function TBuffer.MakeUnique: PBuffer;
  var
    refs: LongInt;
  begin
    refs:=AddRef;

    if Refs>2 then
      MakeUnique:=Clone()
    else
      MakeUnique:=@Self;

    DecRef;
  end;

function TBuffer.Expand(AHeader, ATail: SizeInt): PBuffer;
  var
    res: PBuffer;
  begin
    res:=self.MakeUnique();

    if assigned(res) and
       (AHeader <> 0) then
      res:=res^.ExpandHeader(AHeader);

    if assigned(res) and
       (ATail <> 0) then
      res:=res^.ExpandTail(ATail);

    Expand:=res;
  end;

function TBuffer.ExpandHeader(AHeader: SizeInt): PBuffer;
  var
    NewBuf: PBuffer;
    LeftOver: Integer;
  begin
    // Expand in current place
    if (bfOwnsMem in Flags) and
       (Size<DataSize) and
       ((not (bfWritten in Flags)) or
        (Offset>0)) then
      begin
        if bfWritten in Flags then
          LeftOver:=Offset
        else
          LeftOver:=DataSize-Size;

        if LeftOver>AHeader then
          LeftOver:=AHeader;

        inc(Size, LeftOver);
        dec(offset, LeftOver);
        if Offset<0 then
          offset:=0;

        dec(AHeader, LeftOver);
      end;

    if AHeader<=0 then
      NewBuf:=@self
    else
      begin
        NewBuf:=AllocateBuffer(AHeader);
        if assigned(NewBuf) then
          begin
            NewBuf^.Offset:=NewBuf^.DataSize-NewBuf^.Size;
            NewBuf^.Concat(@self);
          end
        else
          DecRef;
      end;

    ExpandHeader:=NewBuf;
  end;

function TBuffer.ExpandTail(ATail: SizeInt): PBuffer;
  var
    NewBuf: PBuffer;
  begin
    if (bfWritten in Flags) or
       (not (bfOwnsMem in Flags)) or
       ((ATail+Size)>DataSize) then
      begin
        NewBuf:=AllocateBuffer(ATail);
        if assigned(NewBuf) then
          begin
            Concat(NewBuf);
            NewBuf:=@self;
          end
        else
          begin
            DecRef;
            NewBuf:=nil;
          end;
      end
    else
      begin
        inc(Size, ATail);
        NewBuf:=@self;
      end;
    ExpandTail:=NewBuf;
  end;

function TBuffer.Contract(AHeader, ATail: SizeInt): PBuffer;
  var
    res: PBuffer;
  begin
    res:=self.MakeUnique();

    if AHeader <> 0 then
      res:=res^.ContractHeader(AHeader);

    if assigned(res) and
       (ATail <> 0) then
      res:=res^.ContractTail(ATail);

    Contract:=res;
  end;

function TBuffer.ContractHeader(AHeader: SizeInt): PBuffer;
  var
    res, n: PBuffer;
    LeftOver: SizeInt;
  begin
    res:=self.MakeUnique;

    while (AHeader>0) and
          assigned(res) do
      begin
        LeftOver:=AHeader;
        if LeftOver>=res^.Size then
          LeftOver:=res^.Size;

        dec(res^.Size, LeftOver);
        inc(res^.Offset, LeftOver);
        Dec(AHeader, LeftOver);

        if res^.size<=0 then
          begin
            n:=res^.Next;

            res^.Next:=nil;
            res^.DecRef;

            res:=n;
          end
        else
          break;
      end;

    ContractHeader:=res;
  end;

function TBuffer.ContractTail(ATail: SizeInt): PBuffer;
  begin
    ContractTail:=@self;
  end;

function TBuffer.Write(const ABuf; ACount, AOffset: SizeInt): SizeInt;
  var
    p: PBuffer;
    pb: PByte;
    LeftOver, res: SizeInt;
  begin
    p:=@self;

    while assigned(p) and
          (AOffset>0) do
      begin
        if AOffset>=p^.Size then
          begin
            dec(AOffset,p^.Size);
            p:=p^.Next;
          end
        else
          break;
      end;

    res:=0;
    pb:=@ABuf;

    while assigned(p) and
          (ACount>0) do
      begin
        LeftOver:=p^.Size-AOffset;
        if LeftOver>ACount then
          LeftOver:=ACount;

        include(p^.Flags, bfWritten);
        Move(pb^, p^.Data[p^.Offset+AOffset], LeftOver);

        inc(pb, LeftOver);
        dec(ACount, LeftOver);
        inc(res, LeftOver);

        AOffset:=0;

        p:=p^.next;
      end;

    Write:=res;
  end;

function TBuffer.WriteZero(ACount, AOffset: SizeInt): SizeInt;
  var
    p: PBuffer;
    LeftOver, res: SizeInt;
  begin
    p:=@self;

    while assigned(p) and
          (AOffset>0) do
      begin
        if AOffset>=p^.Size then
          begin
            dec(AOffset,p^.Size);
            p:=p^.Next;
          end
        else
          break;
      end;

    res:=0;

    while assigned(p) and
          (ACount>0) do
      begin
        LeftOver:=p^.Size-AOffset;

        if LeftOver>ACount then
          LeftOver:=ACount;

        include(p^.Flags, bfWritten);
        FillChar(p^.Data[p^.Offset+AOffset], LeftOver, 0);

        dec(ACount, LeftOver);
        inc(res, LeftOver);

        AOffset:=0;

        p:=p^.next;
      end;

    WriteZero:=res;
  end;

function TBuffer.Read(var ABuf; ACount, AOffset: SizeInt): SizeInt;
  var
    p: PBuffer;
    pb: PByte;
    LeftOver, res: SizeInt;
  begin
    p:=@self;

    while assigned(p) and
          (AOffset>0) do
      begin
        if AOffset>=p^.Size then
          begin
            dec(AOffset,p^.Size);
            p:=p^.Next;
          end
        else
          break;
      end;

    pb:=@ABuf;
    res:=0;

    while assigned(p) and
          (ACount>0) do
      begin
        LeftOver:=p^.Size-AOffset;

        if LeftOver>ACount then
          LeftOver:=ACount;

        Move(p^.Data[p^.Offset+AOffset], pb^, LeftOver);

        inc(pb, LeftOver);
        dec(ACount, LeftOver);
        inc(res, LeftOver);

        AOffset:=0;

        p:=p^.next;
      end;

    Read:=res;
  end;

procedure InitBuffers;
  var
    i: NativeInt;
  begin
    for i := 0 to BufferCount-2 do
      BufferStorage[i].Next:=@BufferStorage[i+1];
    BufferStorage[BufferCount-1].Next:=nil;

    FreeBuffers:=@BufferStorage[0];


    for i := 0 to DescriptorCount-2 do
      Descriptors[i].Next:=@Descriptors[i+1];
    Descriptors[DescriptorCount-1].Next:=nil;

    FreeDescriptors:=@Descriptors[0];
  end;

initialization
  InitBuffers;

end.