unit linuxraw;

{$mode objfpc}{$H+}

interface

uses
  unixtype, Sockets,
  fpethbuf, fpethtypes;

procedure Start;
procedure Stop;

function Recv: PBuffer;
function Send(AData: pointer; ABuffer: PBuffer): TNetResult;

implementation

uses
  ctypes;

type
  sockaddr_ll = packed record
    sll_family: word;   { Always AF_PACKET }
    sll_protocol: word; { Physical layer protocol }
    sll_ifindex: cint;  { Interface number }
    sll_hatype: word;   { Header type }
    sll_pkttype: byte;  { Packet type }
    sll_halen: byte;    { Length of address }
    sll_addr: array[0..7] of byte;  { Physical layer address }
  end;

const
  ETH_P_ALL = 3;
  SIOCGIFINDEX = $8933;

var
  sockfd: unixtype.cint;

{$packrecords C}

type
  ifreq = record
    ifrn_name: array[0..15] of char;
    ifru_ivalue: cint;
  end;

procedure Start;
  var
    ifr: ifreq;
    timeout: timespec;
  begin
    sockfd:=fpsocket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    timeout.tv_nsec:=100*1000*1000;
    timeout.tv_sec:=0;
    fpsetsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, @timeout, sizeof(timeout));
  end;

procedure Stop;
  begin
    CloseSocket(sockfd);
  end;

function Recv: PBuffer;
  var
    Data: array[0..1024*16-1] of Byte;
    rcv: ssize_t;
    buf: PBuffer;
    from: sockaddr_ll;
    fs: socklen_t;
  begin
    fs:=sizeof(from);
    rcv:=fprecvfrom(sockfd, @data[0], length(data), 0, @from, @fs);

    if rcv>0 then
      begin
        buf:=AllocateBuffer(rcv, plPhy);
        if assigned(buf) then
          begin
            buf^.write(data[0], rcv, 0);
            exit(buf);
          end
        else
          WriteLn('Dropped input frame');
      end;

    exit(nil);
  end;

function Send(AData: pointer; ABuffer: PBuffer): TNetResult;
  var
    buf: array of byte;
    tox: sockaddr_ll;
  begin
    SetLength(buf, ABuffer^.TotalSize);
    ABuffer^.Read(buf[0], length(buf), 0);
    ABuffer^.DecRef;

    fillchar(tox, sizeof(tox), 0);
    //tox.sll_family:=AF_PACKET;
    //tox.sll_protocol:=1;
    //tox.sll_pkttype:=4;
    move(buf[0], tox.sll_addr[0], 6);
    tox.sll_halen:=6;
    tox.sll_ifindex:=2;

    if fpsendto(sockfd, @buf[0], length(buf), 0, @tox, sizeof(tox))=length(buf) then
      exit(nrOk)
    else
      exit(nrQueueFull);
  end;

end.

