require 'socket'
require 'netlink/constants'
require 'netlink/message'

module Netlink
  class NLSocket
    DEFAULT_TIMEOUT = 2

    SOCKADDR_PACK = "SSLL".freeze #:nodoc:
    SOCKADDR_SIZE = 12 # :nodoc:

    # Generate a sockaddr_nl. Pass :pid and/or :groups.
    def self.sockaddr(opt={})
      [Socket::AF_NETLINK, 0, opt[:pid] || 0, opt[:groups] || 0].pack("SSLL")
    end

    # Default sockaddr_nl with 0 pid (send to kernel) and no multicast groups
    SOCKADDR_DEFAULT = sockaddr.freeze

    # Check the sockaddr on a received message. Raises an error if the AF
    # is not AF_NETLINK or the PID is not 0 (this is important for security)
    def self.parse_sockaddr(str)
      af, pad, pid, groups = str.unpack(SOCKADDR_PACK)
      raise "Bad AF #{af}!" if af != Socket::AF_NETLINK
      raise "Bad PID #{pid}!" if pid != 0
    end

    attr_accessor :socket
    attr_accessor :seq
    attr_accessor :pid

    # Create a new Netlink socket. Pass in chosen protocol:
    #   :protocol => Netlink::NETLINK_ARPD
    #   :protocol => Netlink::NETLINK_FIREWALL
    #   :protocol => Netlink::NETLINK_IP6_FW
    #   :protocol => Netlink::NETLINK_NFLOG
    #   :protocol => Netlink::NETLINK_ROUTE
    #   :protocol => Netlink::NETLINK_ROUTE6
    #   :protocol => Netlink::NETLINK_TAPBASE
    #   :protocol => Netlink::NETLINK_TCPDIAG
    #   :protocol => Netlink::NETLINK_XFRM
    # Other options:
    #   :groups => N (subscribe to multicastgroups, default to 0)
    #   :seq => N (override initial sequence number)
    #   :pid => N (override PID)
    #   :timeout => N (seconds, default to DEFAULT_TIMEOUT. Pass nil for no timeout)
    def initialize(opt)
      @socket ||= opt[:socket] || ::Socket.new(
        Socket::AF_NETLINK,
        Socket::SOCK_DGRAM,
        opt[:protocol] || (raise "Missing :protocol")
      )
      @socket.bind(NLSocket.sockaddr(opt)) unless opt[:socket]
      @seq = opt[:seq] || Time.now.to_i
      @pid = opt[:pid] || $$
      @timeout = opt.has_key?(:timeout) ? opt[:timeout] : DEFAULT_TIMEOUT
    end

    # Send a Netlink::Message object over the socket
    #   obj:: the object to send (responds to #to_s)
    #   flags:: message header flags, default NLM_F_REQUEST
    #   sockaddr:: destination sockaddr, defaults to pid=0 and groups=0
    #   seq:: sequence number, defaults to bump internal sequence
    #   pid:: pid, defaults to $$
    #   vflags:: sendmsg flags, defaults to 0
    def send_request(type, obj, flags=NLM_F_REQUEST, sockaddr=SOCKADDR_DEFAULT, seq=(@seq += 1), pid=@pid, vflags=0, controls=[])
      @socket.sendmsg(
        build_message(type, obj, flags, seq, pid),
        vflags, sockaddr, *controls
      )
    end

    NLMSGHDR_PACK = "LSSLL".freeze  # :nodoc:
    NLMSGHDR_SIZE = 16 # :nodoc:

    # Build a message comprising header+body. It is not padded at the end.
    def build_message(type, body, flags=NLM_F_REQUEST, seq=(@seq += 1), pid=@pid)
      body = body.to_s
      header = [
        body.bytesize + NLMSGHDR_SIZE,
        type, flags, seq, pid
      ].pack(NLMSGHDR_PACK)
      # assume the header is already aligned
      header + body
    end

    # Send multiple Netlink::Message objects in a single message. They
    # need to share the same type and flags, and will be sent with sequential
    # sequence nos.
    def send_requests(type, objs, flags=NLM_F_REQUEST, pid=@pid)
      objs.each_with_index do |obj, index|
        if index < objs.size - 1
          data << build_message(type, obj, flags|NLM_F_MULTI, @seq+=1, pid)
          Message.pad(data)
        else
          data << build_message(type, obj, flags, @seq+=1, pid)
        end
      end
    end

    # Discard all waiting messages
    def flush
      while select([@socket], nil, nil, 0)
        @socket.recvmsg
      end
    end

    # Loop receiving responses until Netlink::Message::Done, and yielding
    # the objects found. Also filters so that only expected pid and seq
    # are accepted.
    #
    # (Compare: rtnl_dump_filter_l in lib/libnetlink.c)
    def receive_until_done(timeout=@timeout, junk_handler=nil, &blk) #:yields: type, flags, obj
      res = []
      blk ||= lambda { |type, flags, obj| res << obj if obj }
      junk_handler ||= lambda { |obj| warn "Discarding junk message #{obj}" } if $VERBOSE
      loop do
        receive_response(timeout) do |type, flags, seq, pid, obj|
          if pid != @pid || seq != @seq
            junk_handler[obj] if junk_handler
            next
          end
          case type
          when NLMSG_DONE
            return res
          when NLMSG_ERROR
            raise "Netlink Error received"
          end
          blk.call(type, flags, obj)
        end
      end
    end
    
    # Receive one datagram from kernel. If a block is given, then yield
    # Netlink::Message objects (maybe multiple times if the datagram
    # includes multiple netlink messages).
    #
    #   receive_response { |msg| p msg }
    def receive_response(timeout=@timeout, &blk) # :yields: type, flags, seq, pid, Message
      if select([@socket], nil, nil, timeout)
        mesg, sender, rflags, controls = @socket.recvmsg
        raise EOFError unless mesg
        NLSocket.parse_sockaddr(sender.to_sockaddr)
        parse_yield(mesg, &blk)
      else
        raise "Timeout"
      end
    end

    # Parse message(s) in a string buffer and yield message object, flags,
    # seq and pid
    def parse_yield(mesg) # :yields: type, flags, seq, pid, Message
      dechunk(mesg) do |h_type, h_flags, h_seq, h_pid, data|
        klass = Message::CODE_TO_MESSAGE[h_type]
        yield h_type, h_flags, h_seq, h_pid, klass && klass.parse(data)
      end
    end  

    # Take message(s) in a string buffer and yield fields in turn
    def dechunk(mesg) # :yields: type, flags, seq, pid, data
      ptr = 0
      while ptr < mesg.bytesize
        raise "Truncated netlink header!" if ptr + NLMSGHDR_SIZE > mesg.bytesize
        len, type, flags, seq, pid = mesg[ptr,NLMSGHDR_SIZE].unpack(NLMSGHDR_PACK)
        STDERR.puts "  len=#{len}, type=#{type}, flags=#{flags}, seq=#{seq}, pid=#{pid}" if $DEBUG
        raise "Truncated netlink message!" if ptr + len > mesg.bytesize
        data = mesg[ptr+NLMSGHDR_SIZE, len-NLMSGHDR_SIZE]
        STDERR.puts "  data=#{data.inspect}" if $DEBUG && !data.empty?
        yield type, flags, seq, pid, data
        ptr = ptr + Message.align(len)
        break unless flags & Netlink::NLM_F_MULTI
      end
    end
  end
end
