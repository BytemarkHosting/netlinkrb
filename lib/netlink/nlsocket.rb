require 'socket'
require 'netlink/constants'
require 'netlink/message'

module Netlink
  ERRNO_MAP = {}  #:nodoc:
  Errno.constants.each do |k|
    klass = Errno.const_get(k)
    next unless klass.is_a?(Class) and Class.const_defined?(:Errno)
    ERRNO_MAP[klass::Errno] = klass
  end

  # NLSocket provides low-level sending and receiving of messages across
  # a netlink socket, adding headers to sent messages and parsing
  # received messages.
  class NLSocket
    DEFAULT_TIMEOUT = 5

    SOCKADDR_PACK = "SSLL".freeze #:nodoc:

    # Generate a sockaddr_nl. Pass :pid and/or :groups.
    def self.sockaddr(opt={})
      [Socket::AF_NETLINK, 0, opt[:pid] || 0, opt[:groups] || 0].pack("SSLL")
    end

    # Default sockaddr_nl with 0 pid (send to kernel) and no multicast groups
    SOCKADDR_DEFAULT = sockaddr.freeze

    # Check the sockaddr on a received message. Raises an error if the AF
    # is not AF_NETLINK or the PID is not 0 (this is important for security)
    def self.check_sockaddr(str)
      af, pad, pid, groups = str.unpack(SOCKADDR_PACK)
      raise "Bad AF #{af}!" if af != Socket::AF_NETLINK
      raise "Bad PID #{pid}!" if pid != 0
    end

    attr_accessor :socket	# the underlying Socket
    attr_accessor :seq		# the last sequence number used
    attr_accessor :pid		# default pid to include in message headers
    attr_accessor :timeout	# default timeout when receiving message

    # Create a new Netlink socket. Pass in chosen protocol:
    #   :protocol => Netlink::NETLINK_ARPD
    #   :protocol => Netlink::NETLINK_FIREWALL
    #   :protocol => Netlink::NETLINK_ROUTE
    # etc. Other options:
    #   :groups => N (subscribe to multicast groups, default to 0)
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

    # Generate the next sequence number
    def next_seq
      @seq = (@seq + 1) & 0xffffffff
    end
    
    # Add a header and send a single message over the socket.
    #   type:: the message type code
    #   msg:: the message to send (without header)
    #   flags:: message header flags, default NLM_F_REQUEST
    #   sockaddr:: destination sockaddr, defaults to pid=0 and groups=0
    #   seq:: sequence number, defaults to bump internal sequence
    #   pid:: pid, defaults to $$
    #   vflags:: sendmsg flags, defaults to 0
    # Normally 'msg' would be an instance of a Netlink::Message subclass,
    # although in fact any object which respond to #to_s will do (if you
    # want to pack the message body yourself).
    def send_request(type, msg, flags=NLM_F_REQUEST, sockaddr=SOCKADDR_DEFAULT, seq=next_seq, pid=@pid, vflags=0, controls=[])
      @socket.sendmsg(
        build_message(type, msg, flags, seq, pid),
        vflags, sockaddr, *controls
      )
    end

    # Build a message comprising header+body. It is not padded at the end.
    def build_message(type, body, flags=NLM_F_REQUEST, seq=next_seq, pid=@pid)
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
    def send_requests(type, msgs, flags=NLM_F_REQUEST, pid=@pid)
      msgs.each_with_index do |msg, index|
        if index < msgs.size - 1
          data << build_message(type, msg, flags|NLM_F_MULTI, next_seq, pid)
          Message.nlmsg_pad(data)
        else
          data << build_message(type, msg, flags, next_seq, pid)
        end
      end
    end

    # Discard all waiting messages
    def drain
      while select([@socket], nil, nil, 0)
        mesg, sender, rflags, controls = @socket.recvmsg
        raise EOFError unless mesg
      end
    end

    # Loop receiving responses until a DONE message is received (or you
    # break out of the loop, or a timeout exception occurs). Filters out
    # messages with unexpected pid and seq. If you pass an expected_type then
    # messages other than this type will be discarded too.
    #
    # Yields Netlink::Message objects, or if no block is given, returns an
    # array of those objects. If you provide a junk_handler then it will be
    # called for discarded messages.
    #
    # (Compare: rtnl_dump_filter_l in lib/libnetlink.c)
    def receive_until_done(expected_type=nil, timeout=@timeout, junk_handler=nil, &blk) #:yields: msg
      res = []
      blk ||= lambda { |msg| res << msg }
      junk_handler ||= lambda { |type, flags, seq, pid, msg|
        warn "Discarding junk message (#{type}, #{flags}, #{seq}, #{pid}) #{msg.inspect}" } if $VERBOSE
      loop do
        receive_response(timeout) do |type, flags, seq, pid, msg|
          if pid != @pid || seq != @seq
            junk_handler[type, flags, seq, pid, msg] if junk_handler
            next
          end
          case type
          when NLMSG_DONE
            return res
          when NLMSG_ERROR
            raise ERRNO_MAP[-msg.error] || "Netlink Error: #{msg.inspect}"
          end
          if expected_type && type != expected_type
            junk_handler[type, flags, seq, pid, msg] if junk_handler
            next
          end
          blk.call(msg) if msg
        end
      end
    end

    # Loop infinitely receiving messages of given type(s), ignoring pid and seq.
    # Raises an exception on NLMSG_ERROR.
    def receive_stream(*expected_types)
      loop do
        receive_response(nil) do |type, flags, seq, pid, msg|
          if expected_types.include?(type)
            yield msg
          elsif type == NLMSG_ERROR
            raise ERRNO_MAP[-msg.error] || "Netlink Error: #{msg.inspect}"
          else
            warn "Received unexpected message type #{type}: #{msg.inspect}"
          end
        end
      end
    end
    
    # Receive one datagram from kernel. Yield header fields plus
    # Netlink::Message objects (maybe multiple times if the datagram
    # includes multiple netlink messages). Raise an exception if no
    # datagram received within the specified or default timeout period;
    # pass nil for infinite timeout.
    #
    #   receive_response { |type, flags, seq, pid, msg| p msg }
    def receive_response(timeout=@timeout, &blk) # :yields: type, flags, seq, pid, Message
      if select([@socket], nil, nil, timeout)
        mesg, sender, rflags, controls = @socket.recvmsg
        raise EOFError unless mesg
        NLSocket.check_sockaddr(sender.to_sockaddr)
        parse_yield(mesg, &blk)
      else
        raise "Timeout"
      end
    end

    # Parse netlink packet in a string buffer. Yield header fields plus
    # a Netlink::Message-derived object for each message. For unknown message
    # types it will yield a raw String, or nil if there is no message body.
    def parse_yield(mesg) # :yields: type, flags, seq, pid, Message-or-nil
      dechunk(mesg) do |h_type, h_flags, h_seq, h_pid, data|
        klass = Message::CODE_TO_MESSAGE[h_type]
        yield h_type, h_flags, h_seq, h_pid,
              if klass
                klass.parse(data)
              elsif data && data != EMPTY_STRING
                data
              else
                nil
              end
      end
    end

    # Parse netlink packet in a string buffer. Yield header and body
    # components for each message in turn.
    def dechunk(mesg) # :yields: type, flags, seq, pid, data
      ptr = 0
      while ptr < mesg.bytesize
        raise "Truncated netlink header!" if ptr + NLMSGHDR_SIZE > mesg.bytesize
        len, type, flags, seq, pid = mesg[ptr,NLMSGHDR_SIZE].unpack(NLMSGHDR_PACK)
        STDERR.puts "  len=#{len}, type=#{type}, flags=#{flags}, seq=#{seq}, pid=#{pid}" if $DEBUG
        raise "Truncated netlink message!" if ptr + len > mesg.bytesize
        raise "Invalid netlink len!" if len < NLMSGHDR_SIZE
        data = mesg[ptr+NLMSGHDR_SIZE, len-NLMSGHDR_SIZE]
        STDERR.puts "  data=#{data.inspect}" if $DEBUG && !data.empty?
        yield type, flags, seq, pid, data
        ptr = ptr + Message.nlmsg_align(len)
        break unless flags & Netlink::NLM_F_MULTI
      end
    end
  end
end
