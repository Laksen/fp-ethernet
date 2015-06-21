unit fpethbuf;

interface

{$modeswitch AdvancedRecords}

type
  TProtocolLayer = (plPhy, plLink, plNetwork, plApplication);

  TBufferFlag = (bfWritten, bfOwnsMem);
  TBufferFlags = set of TBufferFlag;

  PBuffer = ^TBuffer;

  TBufferWriter = record
    Desc: PBuffer;
    Offset: SizeInt;

    procedure Advance(ABytes: SizeInt);

    procedure Write(const Data; Size: SizeInt);
    procedure Read(out Data; Size: SizeInt);

    procedure WriteZeros(Size: SizeInt);
    procedure WriteByte(Val: byte);
    procedure WriteWord(Val: word);
    procedure WriteLongword(Val: longword);

    function ReadByte: byte;
    function ReadWord: word;
    function ReadLongWord: longword;
  end;

  { TBuffer }

  TBuffer = record
    Data: PByte;
    DataSize: SizeInt;

    Offset, Size: SizeInt;

    Next: PBuffer;

    RefCnt: longint;

    Flags: TBufferFlags;

    procedure DumpBuffer;

    procedure Free;

    function AddRef: longint;
    procedure DecRef;

    function TotalSize: SizeInt;

    function Concat(ABuffer: PBuffer): PBuffer;
    function ConcatSmart(ABuffer: PBuffer): PBuffer;

    procedure CopyTo(AOffset, ACount: SizeInt; ADest: PBuffer; ADestOffset: sizeint);
    function MakeUnique: PBuffer;

    function GetWriter: TBufferWriter;

    function Expand(AHeader, ATail: SizeInt): PBuffer;

    function Contract(AHeader, ATail: SizeInt): PBuffer;

    function Write(const ABuf; ACount, AOffset: SizeInt): SizeInt;
    function WriteZero(ACount, AOffset: SizeInt): SizeInt;
    function Read(out ABuf; ACount, AOffset: SizeInt): SizeInt;
  private
    function Clone: PBuffer;

    function ExpandHeader(AHeader: SizeInt): PBuffer;
    function ExpandTail(ATail: SizeInt): PBuffer;

    function ContractHeader(AHeader: SizeInt): PBuffer;
    function ContractTail(ATail: SizeInt): PBuffer;
  end;

function AllocateWindow(ABuffer: PBuffer): PBuffer;
function AllocateBuffer(ASize: SizeInt; ALayerHint: TProtocolLayer = plApplication): PBuffer;
function AllocateStaticBuffer(AData: Pointer; ASize: SizeInt): PBuffer;

var
  DescCount: longint;

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

    if assigned(desc) then
      inc(DescCount);

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

    if assigned(desc) then
      dec(DescCount);
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
    Cnt: sizeint;
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

procedure TBufferWriter.Advance(ABytes: SizeInt);
  var
    Left: SizeInt;
  begin
    while (ABytes>0) and
          assigned(Desc) do
      begin
        Left:=Desc^.Size-Offset;
        if Left>ABytes then
          begin
            inc(Offset,ABytes);
            exit;
          end
        else
          begin
            Desc:=Desc^.Next;
            Offset:=0;
            Dec(ABytes, Left);
          end;
      end;
  end;

procedure TBufferWriter.Write(const Data; Size: SizeInt);
  begin
    Desc^.Write(Data, Size, Offset);
    Advance(Size);
  end;

procedure TBufferWriter.Read(out Data; Size: SizeInt);
  begin
    Desc^.Read(Data, Size, Offset);
    Advance(Size);
  end;

procedure TBufferWriter.WriteZeros(Size: SizeInt);
  begin
    Desc^.WriteZero(Size, Offset);
    Advance(Size);
  end;

procedure TBufferWriter.WriteByte(Val: byte);
  begin
    Write(Val, 1);
  end;

procedure TBufferWriter.WriteWord(Val: word);
  begin
    Write(val, 2);
  end;

procedure TBufferWriter.WriteLongword(Val: longword);
  begin
    Write(val, 4);
  end;

function TBufferWriter.ReadByte: byte;
  begin
    Read(result, 1);
  end;

function TBufferWriter.ReadWord: word;
  begin
    Read(result, 2);
  end;

function TBufferWriter.ReadLongWord: longword;
  begin
    Read(result, 4);
  end;

procedure TBuffer.DumpBuffer;
  var
    p: PBuffer;
    f: TBufferFlag;
    fst: Boolean;
  begin
    Writeln('Buffer size: ', TotalSize);
    p:=@self;

    while assigned(p) do
      begin
        system.write(' ',p^.Size:3, ' - (',p^.RefCnt,',',p^.Offset,') - [');

        fst:=true;
        for f in p^.Flags do
          begin
            if not fst then system.write(',');
            system.write(f);
            fst:=false;
          end;

        writeln(']');

        p:=p^.next;
      end;
  end;

procedure TBuffer.Free;
  var
    cur: PBuffer;
  begin
    cur:=@Self;

    if bfOwnsMem in cur^.Flags then
      FreeBuffer(PDataBuffer(cur^.Data));

    FreeDescriptor(cur);
  end;

function TBuffer.AddRef: longint;
  var
    p: PBuffer;
    ref,tmp: LongInt;
  begin
    p:=@self;
    ref:=0;

    while assigned(p) do
      begin
        if IsConcurrent then
          tmp:=InterLockedIncrement(p^.RefCnt)
        else
          begin
            inc(p^.RefCnt);
            tmp:=p^.RefCnt;
          end;

        if tmp>ref then
          ref:=tmp;

        p:=p^.next;
      end;

    AddRef:=ref;
  end;

procedure TBuffer.DecRef;
  var
    OldCnt: LongInt;
    p,p2: PBuffer;
  begin
    p:=@self;

    while assigned(p) do
      begin
        p2:=p^.next;

        if IsConcurrent then
          OldCnt:=InterLockedDecrement(p^.RefCnt)
        else
          begin
            OldCnt:=p^.RefCnt;
            Dec(p^.RefCnt);
          end;

        if OldCnt < 1 then
          p^.Free;

        p:=p2;
      end;
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

function TBuffer.Concat(ABuffer: PBuffer): PBuffer;
  var
    p: PBuffer;
  begin
    p:=self.MakeUnique;

    while assigned(p^.Next) do
      p:=p^.next;

    p^.next:=ABuffer;

    result:=p;
  end;

function TBuffer.ConcatSmart(ABuffer: PBuffer): PBuffer;
  var
    p: PBuffer;
    ts,ts2: SizeInt;
  begin
    ts:=ABuffer^.TotalSize;
    ts2:=TotalSize;
    p:=self.ExpandTail(ts);

    if not assigned(p) then
      exit(nil);

    ABuffer^.CopyTo(0, ts, p, ts2);

    result:=p;
  end;

procedure TBuffer.CopyTo(AOffset, ACount: SizeInt; ADest: PBuffer; ADestOffset: sizeint);
  var
    os, od,
    ms, md: SizeInt;
    pd,ps: PBuffer;
  begin
    ps:=@self;
    pd:=ADest;

    os:=AOffset;
    while assigned(ps) and
          (ps^.size<=os) do
      begin
        dec(os,ps^.size);
        ps:=ps^.Next;
      end;

    od:=ADestOffset;
    while assigned(pd) and
          (pd^.size<=od) do
      begin
        dec(od,pd^.size);
        pd:=pd^.Next;
      end;

    while assigned(ps) and
          assigned(pd) and
          (ACount>0) do
      begin
        ms:=ps^.Size-os;
        md:=pd^.Size-od;

        if (ms>ACount) then ms:=ACount;
        if (md>ACount) then md:=ACount;

        if ms=md then
          begin
            move(ps^.Data[ps^.Offset+os], pd^.Data[pd^.Offset+od], ms);

            dec(ACount, ms);

            ps:=ps^.Next; os:=0;
            pd:=pd^.Next; od:=0;
          end
        else if ms<md then
          begin
            move(ps^.Data[ps^.Offset+os], pd^.Data[pd^.Offset+od], ms);

            dec(ACount, ms);

            ps:=ps^.next; os:=0;
            inc(od, ms);
          end
        else
          begin
            move(ps^.Data[ps^.Offset+os], pd^.Data[pd^.Offset+od], md);

            dec(ACount, md);

            inc(os, md);
            pd:=pd^.next; od:=0;
          end;
      end;
  end;

function TBuffer.Clone: PBuffer;
  var
    res: PBuffer;
    ts: SizeInt;
  begin
    ts:=TotalSize;
    res:=AllocateBuffer(TotalSize, plPhy);

    CopyTo(0, ts, res, 0);

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

function TBuffer.GetWriter: TBufferWriter;
  begin
    Include(Flags, bfWritten);
    result.Desc:=@self;
    result.Offset:=0;
  end;

function TBuffer.Expand(AHeader, ATail: SizeInt): PBuffer;
  var
    res: PBuffer;
  begin
    if (AHeader=0) and (ATail=0) then
      exit(@self);

    res:=MakeUnique;

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
    if ((Flags*[bfOwnsMem])=[bfOwnsMem]) and
       (RefCnt<2) and
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
        NewBuf:=AllocateBuffer(AHeader, plPhy);
        if assigned(NewBuf) then
          begin
            NewBuf^.Offset:=NewBuf^.DataSize-NewBuf^.Size;
            NewBuf:=NewBuf^.Concat(@self);
          end
        else
          DecRef;
      end;

    ExpandHeader:=NewBuf;
  end;

function TBuffer.ExpandTail(ATail: SizeInt): PBuffer;
  var
    NewBuf,p,p2: PBuffer;
    leftOver: SizeInt;
  begin
    p2:=MakeUnique;
    p:=p2;

    while assigned(p^.Next) do
      p:=p^.next;

    if bfOwnsMem in p^.Flags then
      begin
        leftOver:=p^.DataSize-(p^.Size+p^.Offset);

        if leftover>ATail then leftOver:=ATail;

        if (leftOver>0) then
          begin
            inc(p^.size,leftOver);
            dec(ATail,leftOver);
          end;
      end;

    if ATail>0 then
      begin
        NewBuf:=AllocateBuffer(ATail, plPhy);
        if assigned(NewBuf) then
          begin
            NewBuf^.Offset:=0;
            p^.next:=NewBuf;
          end
        else
          begin
            p2^.DecRef;
            p2:=nil;
          end;
      end;

    ExpandTail:=p2;
  end;

function TBuffer.Contract(AHeader, ATail: SizeInt): PBuffer;
  var
    res: PBuffer;
  begin
    if (AHeader=0) and (ATail=0) then
      exit(@self);

    res:=MakeUnique;

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
  var
    left, leftOver: SizeInt;
    p: PBuffer;
    res: PBuffer;
  begin
    res:=self.MakeUnique;

    left:=res^.TotalSize-ATail;
    if left<=0 then
      begin
        if assigned(res^.next) then
          begin
            res^.next^.DecRef;
            res^.next:=nil;
          end;

        res^.Size:=0;
        res^.Offset:=res^.DataSize;
        Exclude(res^.Flags, bfWritten);
      end
    else
      begin
        p:=res;
        while left>0 do
          begin
            leftOver:=left-p^.Size;

            if leftover<0 then
              begin
                if assigned(p^.next) then
                  begin
                    p^.next^.DecRef;
                    p^.next:=nil;
                  end;

                dec(p^.size,-leftOver);
                left:=0;
              end
            else if leftover=0 then
              begin
                if assigned(p^.next) then
                  begin
                    p^.next^.DecRef;
                    p^.next:=nil;
                  end;
                left:=0;
              end
            else
              begin
                dec(left,p^.size);
                p:=p^.next;
              end;
          end;
      end;

    ContractTail:=res;
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

function TBuffer.Read(out ABuf; ACount, AOffset: SizeInt): SizeInt;
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
