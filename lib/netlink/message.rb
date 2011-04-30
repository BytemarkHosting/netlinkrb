require 'netlink/constants'
require 'ipaddr'

module Netlink
  EMPTY_STRING = "".freeze #:nodoc:
  EMPTY_ARRAY  = [].freeze #:nodoc:

  # struct rtnl_link_stats / rtnl_link_stats64
  LinkStats = Struct.new :rx_packets, :tx_packets,
  	:rx_bytes, :tx_bytes,
  	:rx_errors, :tx_errors,
  	:rx_dropped, :tx_dropped,
  	:multicast, :collisions,
  	:rx_length_errors, :rx_over_errors,
  	:rx_crc_errors, :rx_frame_errors,
  	:rx_fifo_errors, :rx_missed_errors,
  	:tx_aborted_errorsr, :tx_carrier_errors,
  	:tx_fifo_errors, :tx_heartbeat_errors,
  	:tx_window_errors,
  	:rx_compressed, :tx_compressed

  # struct rta_cacheinfo
  RTACacheInfo = Struct.new :clntref, :lastuse, :expires, :error, :used, :id, :ts, :tsage
  # struct ifa_cacheinfo
  IFACacheInfo = Struct.new :prefered, :valid, :cstamp, :tstamp
  # struct ifmap
  IFMap = Struct.new :mem_start, :mem_end, :base_addr, :irq, :dma, :port

  # This is the base class from which all Netlink messages are derived.
  # To define a new Netlink message, make a subclass and then call the
  # "field" metaprogramming method to define the parts of the message, in
  # order. The "code" metaprogramming method defines which incoming message
  # types are to be built using this structure.
  #
  # You can then instantiate the message by calling 'new' as usual. It is
  # usually most convenient to pass in a hash of values when creating a message.
  #
  #   class Foo < Message
  #     code 10, 11, 12
  #     field :foo, :char, :default=>255
  #     field :bar, :long
  #   end
  #   msg = Foo.new(:bar => 123)  # or Foo.new("bar" => 123)
  #   msg.bar = 456
  #   msg2 = Foo.new(:qux => 999) # error: no method "qux="
  #   msg2 = Foo.new(msg)         # cloning an existing message
  #
  # Use RtattrMessage for messages which are followed by variable rtattrs.
  class Message
    TYPE_INFO = {} #:nodoc
    
    # Define a new type for use with field and rtattr. You supply the
    # symbolic name for the type, and a set of options. field supports only:
    #    :pattern => "str"    # format string for Array#pack / String#unpack
    #    :default => val      # default (if not 0)
    # rtattr optionally also supports:
    #    :pack => lambda      # code to convert value to binary string
    #    :unpack  => lambda   # code to convert binary string to value
    def self.define_type(name, opt)
      TYPE_INFO[name] = opt
    end
        
    define_type :uchar,   :pattern => "C"
    define_type :uint16,  :pattern => "S"
    define_type :uint32,  :pattern => "L"
    define_type :char,    :pattern => "c"
    define_type :int16,   :pattern => "s"
    define_type :int32,   :pattern => "l"
    define_type :ushort,  :pattern => "S_"
    define_type :uint,    :pattern => "I"
    define_type :ulong,   :pattern => "L_"
    define_type :short,   :pattern => "s_"
    define_type :int,     :pattern => "i"
    define_type :long,    :pattern => "l_"
    define_type :binary,  :pattern => "a*", :default => EMPTY_STRING
    define_type :cstring, :pattern => "Z*", :default => EMPTY_STRING

    define_type :linkstats32,
        :pack   => lambda { |val,obj| val.to_a.pack("L23") },
        :unpack => lambda { |str,obj| LinkStats.new(*(str.unpack("L23"))) }

    define_type :linkstats64,
        :pack   => lambda { |val,obj| val.to_a.pack("Q23") },
        :unpack => lambda { |str,obj| LinkStats.new(*(str.unpack("Q23"))) }

    define_type :rta_cacheinfo,
        :pack   => lambda { |val,obj| val.to_a.pack("L*") },
        :unpack => lambda { |str,obj| RTACacheInfo.new(*(str.unpack("L*"))) }

    define_type :ifa_cacheinfo,
        :pack   => lambda { |val,obj| val.to_a.pack("L*") },
        :unpack => lambda { |str,obj| IFACacheInfo.new(*(str.unpack("L*"))) }

    IFMAP_PACK = "QQQSCC".freeze #:nodoc:
    define_type :ifmap,
        :pack   => lambda { |val,obj| val.to_a.pack(IFMAP_PACK) },
        :unpack => lambda { |str,obj| IFMap.new(*(str.unpack(IFMAP_PACK))) }

    METRIC_PACK = "SSL".freeze #:nodoc:
    METRIC_SIZE = [0,0,0].pack(METRIC_PACK).bytesize #:nodoc:
    define_type :metrics,
        :pack   => lambda { |metrics,obj|
          metrics.map { |code,val| [METRIC_SIZE,code,val].pack(METRIC_PACK) }.join
        },
        :unpack => lambda { |str,obj|
          res = {}  # in kernel the dst.metrics structure is array of u32
          RtattrMessage.unpack_rtattr(str) { |code,val| res[code] = val.unpack("L").first }
          res
        }

    # L2 addresses are presented as ASCII hex. You may optionally include
    # colons, hyphens or dots.
    #    Link.new(:address => "00:11:22:33:44:55")   # this is OK
    define_type :l2addr,
        :pack => lambda { |val,obj| [val.delete(":-.")].pack("H*") },
        :unpack => lambda { |val,obj| val.unpack("H*").first }

    # L3 addresses are presented as IPAddr objects where possible. When
    # setting an address, you may provide an IPAddr object, an IP in readable
    # string form, or an integer. All of the following are acceptable:
    #   Addr.new(:family=>Socket::AF_INET, :address=>IPAddr.new("1.2.3.4"))
    #   Addr.new(:family=>Socket::AF_INET, :address=>"1.2.3.4")
    #   Addr.new(:family=>Socket::AF_INET, :address=>0x01020304)
    # Furthermore, the 'family' will be set automatically if it is unset
    # at the time the message is encoded:
    #   Addr.new(:address=>IPAddr.new("1.2.3.4")).to_s     # ok
    #   Addr.new(:address=>"1.2.3.4").to_s                 # ok
    #   Addr.new(:address=>0x01020304).to_s                # error, unknown family
    #   Addr.new(:address=>"1.2.3.4", :local=>"::1").to_s  # error, mismatched families
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

    def initialize(h=nil)
      if h.instance_of?(self.class)
        @attrs = h.to_hash.dup
      else
        @attrs = self.class::DEFAULTS.dup
        h.each { |k,v| self[k] = v } if h
      end
    end
    
    def to_hash
      @attrs
    end
    
    def each(&blk)
      @attrs.each(&blk)
    end
    
    # Set a field by name. Can use either symbol or string as key.
    def []=(k,v)
      send "#{k}=", v
    end

    # Retrieve a field by name. Must use symbol as key.
    def [](k)
      @attrs[k]
    end
    
    def self.inherited(subclass) #:nodoc:
      subclass.const_set(:FIELDS, [])
      subclass.const_set(:FORMAT, "")
      subclass.const_set(:DEFAULTS, {})
    end

    # Map of numeric message type code => message class
    CODE_TO_MESSAGE = {}

    # Define which message type code(s) to build using this structure
    def self.code(*codes)
      codes.each { |code| CODE_TO_MESSAGE[code] = self }
    end
    
    # Define a field for this message, which creates accessor methods and
    # sets up data required to pack and unpack the structure.
    #    field :foo, :uchar
    #    field :foo, :uchar, :default=>0xff    # use this default value
    def self.field(name, type, opt={})
      info = TYPE_INFO[type]
      self::FIELDS << name
      self::FORMAT << info[:pattern]
      self::DEFAULTS[name] = opt.fetch(:default) { info.fetch(:default, 0) }
      define_method name do
        @attrs.fetch name
      end
      define_method "#{name}=" do |val|
        @attrs.store name, val
      end
    end

    # Returns the packed binary representation of this message (without
    # header, and not padded to NLMSG_ALIGNTO bytes)
    def to_s
      self.class::FIELDS.map { |key| self[key] }.pack(self.class::FORMAT)
    end

    def inspect
      "#<#{self.class} #{@attrs.inspect}>"
    end
    
    # Convert a binary representation of this message into an object instance
    def self.parse(data)
      res = new
      data.unpack(self::FORMAT).zip(self::FIELDS).each do |val, key|
        res[key] = val
      end
      res
    end

    NLMSG_ALIGNTO_1 = NLMSG_ALIGNTO-1 #:nodoc:
    NLMSG_ALIGNTO_1_MASK = ~NLMSG_ALIGNTO_1 #:nodoc:

    # Round up a length to a multiple of NLMSG_ALIGNTO bytes
    def self.align(n)
      (n + NLMSG_ALIGNTO_1) & NLMSG_ALIGNTO_1_MASK
    end

    PADDING = ("\000" * NLMSG_ALIGNTO).freeze #:nodoc:

    # Pad a string up to a multiple of NLMSG_ALIGNTO bytes. Returns str.
    def self.pad(str)
      str << PADDING[0, align(str.bytesize) - str.bytesize]
    end
  end

  # Extends Message to support variable Rtattr attributes. Use 'field'
  # to define the fixed parts of the message, and 'rtattr' to define the
  # permitted rtattrs. We assume that any particular rtattr is not repeated,
  # so we store them in the same underlying hash and create simple accessors
  # for them.
  class RtattrMessage < Message
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
    def self.rtattr(name, code, type=nil, opt={})
      info = TYPE_INFO[type]
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
      @attr_offset ||= Message.align(new.to_s.bytesize)
    end
    
    # Returns the packed binary representation of this message.
    # The main message is processed *after* the rtattrs; this is so that
    # the address family can be set automatically while processing any
    # optional l3 address rtattrs.
    def to_s
      data = ""
      self.class::RTATTRS.each do |code, (name, info)|
        if val = @attrs[name]
          Message.pad(data)  # assume NLMSG_ALIGNTO == NLA_ALIGNTO
          if pack = info[:pack]
            val = pack[val,self]
          elsif pattern = info[:pattern]
            val = Array(val).pack(pattern)
          end
          data << [val.bytesize+RTATTR_SIZE, code].pack(RTATTR_PACK) << val
        end
      end
      data.empty? ? super : Message.pad(super) + data
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
        ptr = Message.align(ptr + len) # assume NLMSG_ALIGNTO == NLA_ALIGNTO
      end
    end
  end

  class Link < RtattrMessage
    code RTM_NEWLINK, RTM_DELLINK, RTM_GETLINK
    field :family, :uchar			# Socket::AF_*
    field :pad, :uchar
    field :type, :ushort			# ARPHRD_*
    field :index, :int
    field :flags, :uint				# IFF_*
    field :change, :uint, :default=>0xffffffff
    rtattr :address, IFLA_ADDRESS, :l2addr
    rtattr :broadcast, IFLA_BROADCAST, :l2addr
    rtattr :ifname, IFLA_IFNAME, :cstring
    rtattr :mtu, IFLA_MTU, :uint32
    rtattr :link, IFLA_LINK, :int32
    rtattr :qdisc, IFLA_QDISC, :cstring
    rtattr :stats32, IFLA_STATS, :linkstats32
    rtattr :cost, IFLA_COST
    rtattr :master, IFLA_MASTER, :uint32
    rtattr :wireless, IFLA_WIRELESS
    rtattr :protinfo, IFLA_PROTINFO, :uchar
    rtattr :txqlen, IFLA_TXQLEN, :uint32
    rtattr :map, IFLA_MAP, :ifmap
    rtattr :weight, IFLA_WEIGHT, :uint32
    rtattr :operstate, IFLA_OPERSTATE, :uchar
    rtattr :linkmode, IFLA_LINKMODE, :uchar
    rtattr :linkinfo, IFLA_LINKINFO # nested
    rtattr :net_ns_pid, IFLA_NET_NS_PID, :uint32
    rtattr :ifalias, IFLA_IFALIAS, :cstring
    rtattr :num_vf, IFLA_NUM_VF, :uint32
    rtattr :vfinfo_list, IFLA_VFINFO_LIST
    rtattr :stats64, IFLA_STATS64, :linkstats64
    rtattr :vf_ports, IFLA_VF_PORTS
    rtattr :port_self, IFLA_PORT_SELF
    
    # Return the best stats available (64bit or 32bit)
    def stats
      stats64 || stats32
    end
  end

  class Addr < RtattrMessage
    code RTM_NEWADDR, RTM_DELADDR, RTM_GETADDR
    field :family, :uchar			# Socket::AF_*
    field :prefixlen, :uchar
    field :flags, :uchar			# IFA_F_*
    field :scope, :uchar			# RT_SCOPE_*
    field :index, :int
    rtattr :address, IFA_ADDRESS, :l3addr
    rtattr :local, IFA_LOCAL, :l3addr
    rtattr :label, IFA_LABEL, :cstring
    rtattr :broadcast, IFA_BROADCAST, :l3addr
    rtattr :anycast, IFA_ANYCAST, :l3addr
    rtattr :cacheinfo, IFA_CACHEINFO, :ifa_cacheinfo
    rtattr :multicast, IFA_MULTICAST, :l3addr
  end

  class Route < RtattrMessage
    code RTM_NEWROUTE, RTM_DELROUTE, RTM_GETROUTE
    field :family, :uchar			# Socket::AF_*
    field :dst_len, :uchar
    field :src_len, :uchar
    field :tos, :uchar
    field :table, :uchar			# table id or RT_TABLE_*
    field :protocol, :uchar			# RTPROT_*
    field :scope, :uchar			# RT_SCOPE_*
    field :type, :uchar				# RTN_*
    field :flags, :uint				# RTM_F_*
    rtattr :dst, RTA_DST, :l3addr
    rtattr :src, RTA_SRC, :l3addr
    rtattr :iif, RTA_IIF, :uint32
    rtattr :oif, RTA_OIF, :uint32
    rtattr :gateway, RTA_GATEWAY, :l3addr
    rtattr :priority, RTA_PRIORITY, :uint32
    rtattr :prefsrc, RTA_PREFSRC, :l3addr
    rtattr :metrics, RTA_METRICS, :metrics
    rtattr :multipath, RTA_MULTIPATH
    rtattr :flow, RTA_FLOW
    rtattr :cacheinfo, RTA_CACHEINFO, :rta_cacheinfo
    rtattr :table2, RTA_TABLE, :uint32   # NOTE: table in two places!
  end
end
