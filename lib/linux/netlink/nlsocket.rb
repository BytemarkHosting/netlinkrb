require 'socket'
require 'linux/constants'
require 'linux/error'
require 'linux/netlink/message'
require 'linux/sendmsg'

module Linux
module Netlink
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
    
    # Create a new Netlink socket, and pass it to the given block.  Ensures
    # the the socket is closed when we're finished.
    def self.open(opt={})
      sock = self.new(opt)
      begin
        yield(sock)
      ensure
        sock.close
      end
    end

    attr_accessor :socket	# the underlying Socket
    attr_accessor :seq		# the last sequence number used
    attr_accessor :pid		# default pid to include in message headers
    attr_accessor :timeout	# default timeout when receiving message
    attr_accessor :junk_handler # proc to log or handle unexpected messages

    # Create a new Netlink socket. Pass in chosen protocol:
    #   :protocol => Linux::NETLINK_ARPD
    #   :protocol => Linux::NETLINK_FIREWALL
    #   :protocol => Linux::NETLINK_ROUTE
    # etc. Other options:
    #   :groups => N (subscribe to multicast groups, default to 0)
    #   :seq => N (override initial sequence number)
    #   :pid => N (override PID)
    #   :timeout => N (seconds, default to DEFAULT_TIMEOUT. Pass nil for no timeout)
    #   :junk_handler => lambda { ... } for unexpected packets
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
      if opt.has_key?(:junk_handler)
        @junk_handler = opt[:junk_handler]
      elsif $VERBOSE
        @junk_handler = lambda { |type, flags, seq, pid, msg|
          warn "Discarding junk message (#{type}, #{flags}, #{seq}, #{pid}) #{msg.inspect}"
        }
      end
    end
    
    # Close the Netlink socket
    def close
      @socket.close
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
    # although in fact any object which respond to #to_str will do (if you
    # want to pack the message body yourself).
    def send_request(type, msg, flags=NLM_F_REQUEST, sockaddr=SOCKADDR_DEFAULT, seq=next_seq, pid=@pid, vflags=0, controls=[])
      @socket.sendmsg(
        build_message(type, msg, flags, seq, pid),
        vflags, sockaddr, *controls
      )
    end

    # Build a message comprising header+body. It is not padded at the end.
    def build_message(type, body, flags=NLM_F_REQUEST, seq=next_seq, pid=@pid)
      body = body.to_str
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

    # Send a command and wait for an Errno::NOERROR as confirmation. Raise
    # an exception if any error message is returned, or on timeout.
    #
    # (Compare: rtnl_talk in lib/libnetlink.c, with answer=NULL)
    def cmd(type, msg, flags=NLM_F_REQUEST, resp_type=NLMSG_ERROR, timeout=@timeout, sockaddr=SOCKADDR_DEFAULT)
      send_request(type, msg, flags|NLM_F_ACK, sockaddr)
      receive_responses(true, timeout) do |type,msg|
        return msg if type == resp_type
        false
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
    # break out of the loop, or a timeout exception occurs). Checks the
    # message type and pid/seq.
    #
    # Yields Netlink::Message objects, or if no block is given, returns an
    # array of those objects.
    #
    # (Compare: rtnl_dump_filter_l in lib/libnetlink.c)
    def receive_until_done(expected_type, timeout=@timeout, &blk) #:yields: msg
      res = []
      blk ||= lambda { |obj| res << obj }
      receive_responses(true, timeout) do |type,msg|
        return res if type == NLMSG_DONE
        if type != expected_type
          false
        else
          blk.call(msg) if msg
        end
      end
    end

    # This is the entry point for protocols which yield an infinite stream
    # of messages (e.g. firewall, ulog). There is no timeout, and
    # the pid/seq are not checked.
    def receive_stream(expected_type) #:yields: msg
      receive_responses(false, nil) do |type, msg|
        if type != expected_type
          false
        else
          yield msg
        end
      end
    end

    # This is the main loop for receiving responses, yielding the type and
    # message object for each received message. It optionally checks the pid/seq
    # and discards those which don't match. If the block returns 'false' then
    # they are also logged as junk.
    #
    # Raises an exception on NLMSG_ERROR (other than Errno::NOERROR), or if
    # no packet received within the specified timeout. Pass nil for infinite
    # timeout.
    def receive_responses(check_pid_seq, timeout=@timeout)
      loop do
        parse_yield(recvmsg(timeout)) do |type, flags, seq, pid, msg|
          if !check_pid_seq || (pid == @pid && seq == @seq)
            Linux.check_error(msg.error) if type == NLMSG_ERROR
            res = yield type, msg
            next unless res == false
          end
          @junk_handler[type, flags, seq, pid, msg] if @junk_handler
        end
      end
    end
    
    # Receive one datagram from kernel. Validates the sender, and returns
    # the raw binary message. Raises an exception on timeout or if the
    # kernel closes the socket.
    def recvmsg(timeout=@timeout)
      if select([@socket], nil, nil, timeout)
        mesg, sender, rflags, controls = @socket.recvmsg
        raise EOFError unless mesg
        sender = sender.to_sockaddr if sender.respond_to? :to_sockaddr
        NLSocket.check_sockaddr(sender)
        mesg
      else
        raise "Timeout"
      end
    end

    # Parse netlink packet in a string buffer. Yield header fields plus
    # a Netlink::Message-derived object for each message. For unknown message
    # types it will yield a raw String, or nil if there is no message body.
    def parse_yield(mesg) # :yields: type, flags, seq, pid, Message-or-nil
      dechunk(mesg) do |type, flags, seq, pid, data|
        klass = Message::CODE_TO_MESSAGE[type]
        yield type, flags, seq, pid,
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
        break unless flags & Linux::NLM_F_MULTI
      end
    end
  end
end
end # module Linux
