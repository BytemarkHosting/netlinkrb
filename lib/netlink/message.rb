require 'netlink/c_struct'
require 'netlink/constants'
require 'ipaddr'

module Netlink
  NLMSGHDR_PACK = "LSSLL".freeze  # :nodoc:
  NLMSGHDR_SIZE = [0,0,0,0,0].pack(NLMSGHDR_PACK).bytesize # :nodoc:

  EMPTY_STRING = "".freeze #:nodoc:
  EMPTY_ARRAY  = [].freeze #:nodoc:

  # This is the base class from which all Netlink messages are derived.
  # To define a new Netlink message, make a subclass and then call the
  # "field" metaprogramming method to define the parts of the message, in
  # order. The "code" metaprogramming method defines which incoming message
  # types are to be built using this structure.
  #
  # Use RtattrMessage instead for messages which are followed by variable rtattrs.
  class Message < CStruct
    # Map of numeric message type code => message class
    CODE_TO_MESSAGE = {}

    # Define which message type code(s) to build using this structure
    def self.code(*codes)
      codes.each { |code| CODE_TO_MESSAGE[code] = self }
    end
    
    NLMSG_ALIGNTO_1 = NLMSG_ALIGNTO-1 #:nodoc:
    NLMSG_ALIGNTO_1_MASK = ~NLMSG_ALIGNTO_1 #:nodoc:

    # Round up a length to a multiple of NLMSG_ALIGNTO bytes
    def self.nlmsg_align(n)
      (n + NLMSG_ALIGNTO_1) & NLMSG_ALIGNTO_1_MASK
    end

    PADDING = ("\000" * NLMSG_ALIGNTO).freeze #:nodoc:

    # Pad a string up to a multiple of NLMSG_ALIGNTO bytes. Returns str.
    def self.nlmsg_pad(str)
      str << PADDING[0, nlmsg_align(str.bytesize) - str.bytesize]
    end
  end

  # Extends Message to support variable Rtattr attributes. Use 'field'
  # to define the fixed parts of the message, and 'rtattr' to define the
  # permitted rtattrs. We assume that any particular rtattr is not repeated,
  # so we store them in the same underlying hash and create simple accessors
  # for them.
  #
  # As well as using :pattern for simple pack/unpack, you can also
  # specify :pack and :unpack lambdas to do higher-level conversion
  # of field values.
  class RtattrMessage < Message
    # L2 addresses are presented as ASCII hex. You may optionally include
    # colons, hyphens or dots.
    #    IFInfo.new(:address => "00:11:22:33:44:55")   # this is OK
    define_type :l2addr,
        :pack => lambda { |val,obj| [val.delete(":-.")].pack("H*") },
        :unpack => lambda { |val,obj| val.unpack("H*").first }

    # L3 addresses are presented as IPAddr objects where possible. When
    # setting an address, you may provide an IPAddr object, an IP in readable
    # string form, or an integer. All of the following are acceptable:
    #   IFAddr.new(:family=>Socket::AF_INET, :address=>IPAddr.new("1.2.3.4"))
    #   IFAddr.new(:family=>Socket::AF_INET, :address=>"1.2.3.4")
    #   IFAddr.new(:family=>Socket::AF_INET, :address=>0x01020304)
    # Furthermore, the 'family' will be set automatically if it is unset
    # at the time the message is encoded:
    #   IFAddr.new(:address=>IPAddr.new("1.2.3.4")).to_s     # ok
    #   IFAddr.new(:address=>"1.2.3.4").to_s                 # ok
    #   IFAddr.new(:address=>0x01020304).to_s                # error, unknown family
    #   IFAddr.new(:address=>"1.2.3.4", :local=>"::1").to_s  # error, mismatched families
    define_type :l3addr,
        :pack => lambda { |val,obj|
          case obj.family
          when Socket::AF_INET, Socket::AF_INET6
            ip = case val
            when IPAddr
              val
            when Integer
              IPAddr.new(val, obj.family)
            else
              IPAddr.new(val)
            end
            raise "Mismatched address family" unless ip.family == obj.family
            ip.hton
          when nil, Socket::AF_UNSPEC
            ip = case val
            when IPAddr
              val
            when Integer
              raise "Missing address family"
            else
              IPAddr.new(val)
            end
            obj.family = ip.family
            ip.hton
          else
            raise "Mismatched address family" if val.is_a?(IPAddr)
            val
          end
        },
        :unpack => lambda { |val,obj|
          case obj.family
          when Socket::AF_INET, Socket::AF_INET6
            IPAddr.new_ntoh(val)
          else
            val
          end
        }

    RTATTR_PACK = "S_S_".freeze #:nodoc:
    RTATTR_SIZE = [0,0].pack(RTATTR_PACK).bytesize #:nodoc:

    def self.inherited(subclass) #:nodoc:
      super
      subclass.const_set(:RTATTRS, {})
    end

    # Define an rtattr. You need to provide the code, and optionally the
    # type (if not provided, it will just be returned as a raw binary string)
    #    rtattr :foo, 12
    #    rtattr :foo, 12, :uint
    def self.rtattr(name, code, type=nil)
      info = find_type(type)
      self::RTATTRS[code] = [name, info]
      define_method name do
        @attrs[name]   # rtattrs are optional, non-existent returns nil
      end
      define_method "#{name}=" do |val|
        @attrs.store name, val
      end
    end

    # Return the byte offset to the first rtattr
    def self.attr_offset
      @attr_offset ||= Message.nlmsg_align(@bytesize)
    end
    
    # Returns the packed binary representation of the entire message.
    # The main message is processed *after* the rtattrs; this is so that
    # the address family can be set automatically while processing any
    # optional l3 address rtattrs.
    def to_s
      data = ""
      self.class::RTATTRS.each do |code, (name, info)|
        if val = @attrs[name]
          Message.nlmsg_pad(data)  # assume NLMSG_ALIGNTO == NLA_ALIGNTO
          if pack = info[:pack]
            val = pack[val,self]
          elsif pattern = info[:pattern]
            val = Array(val).pack(pattern)
          end
          data << [val.bytesize+RTATTR_SIZE, code].pack(RTATTR_PACK) << val
        end
      end
      data.empty? ? super : Message.nlmsg_pad(super) + data
    end
    
    # Convert a binary representation of this message into an object instance.
    # The main message is processed *before* the rtattrs, so that the
    # address family is available for l3 address rtattrs.
    def self.parse(data)
      res = super
      attrs = res.to_hash
      unpack_rtattr(data, attr_offset) do |code, val|
        name, info = self::RTATTRS[code]
        if name
          if !info
            # skip
          elsif unpack = info[:unpack]
            val = unpack[val,res]
          elsif pattern = info[:pattern]
            val = val.unpack(pattern).first
          end
          warn "Duplicate attribute #{name} (#{code}): #{attrs[name].inspect} -> #{val.inspect}" if attrs[name]
          attrs[name] = val
        else
          warn "Unknown attribute #{code}, value #{val.inspect}"
          attrs[code] = val
        end
      end
      res
    end

    # Unpack a string containing a sequence of rtattrs, yielding each in turn.
    def self.unpack_rtattr(data, ptr=0)  #:nodoc:
      while ptr < data.bytesize
        raise "Truncated rtattr header!" if ptr + RTATTR_SIZE > data.bytesize
        len, code = data[ptr, RTATTR_SIZE].unpack(RTATTR_PACK)
        raise "Truncated rtattr body!" if ptr + len > data.bytesize
        raise "Invalid rtattr len!" if len < RTATTR_SIZE
        yield code, data[ptr+RTATTR_SIZE, len-RTATTR_SIZE]
        ptr = Message.nlmsg_align(ptr + len) # assume NLMSG_ALIGNTO == NLA_ALIGNTO
      end
    end
  end

  # struct nlmsgerr (netlink.h)
  class Err < Message
    code NLMSG_ERROR

    field :error, :int
    #field :msg, :pattern => NLMSGHDR_PACK (can't, returns multiple values)
    field :msg_len, :uint32
    field :msg_type, :uint16
    field :msg_flags, :uint16
    field :msg_seq, :uint32
    field :msg_pid, :uint32
  end
end
