require 'netlink/constants'

module Netlink
  # Base class for Netlink messages
  class Message
    # Map of numeric message type code => message class
    CODE_TO_MESSAGE = {}

    # Defines each of the possible field types
    TYPE_INFO = {
      :uchar	=> { :pattern => "C" },
      :uint16	=> { :pattern => "S" },
      :uint32	=> { :pattern => "L" },
      :char	=> { :pattern => "c" },
      :int16	=> { :pattern => "s" },
      :int32	=> { :pattern => "l" },
      :ushort	=> { :pattern => "S_" },
      :uint	=> { :pattern => "I" },
      :ulong	=> { :pattern => "L_" },
      :short	=> { :pattern => "s_" },
      :int	=> { :pattern => "i" },
      :long	=> { :pattern => "l_" },
      :binary	=> { :pattern => "a*", :default => "" },
      :cstring	=> { :pattern => "Z*", :default => "" },
      :stats32	=> { :pattern => "L*", :default => [] },
      :stats64	=> { :pattern => "Q*", :default => [] },
    }

    # You can initialize a message from a Hash or from another
    # instance of itself.
    #
    #   class Foo < Message
    #     field :foo, :char, :default=>255
    #     field :bar, :long
    #   end
    #   msg = Foo.new(:bar => 123)  # or ("bar" => 123)
    #   msg2 = Foo.new(msg)
    #   msg3 = Foo.new(:qux => 999) # error, no method "qux="
    def initialize(h={})
      if h.instance_of?(self.class)
        @attrs = h.to_hash.dup
      else
        @attrs = self.class::DEFAULTS.dup
        h.each { |k,v| self[k] = v }
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

    # Define which message type code(s) use this structure
    def self.code(*codes)
      codes.each { |code| CODE_TO_MESSAGE[code] = self }
    end
    
    # Define a field for this message, which creates accessor methods and
    # sets up data required to pack and unpack the structure.
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

  # This is a class for a Message which is followed by Rtattr key/value pairs.
  # We assume that any particular attribute is not repeated, so it maps to
  # a single attribute in the underlying hash.
  class RtattrMessage < Message
    RTATTR_PACK = "S_S_".freeze #:nodoc:
    RTATTR_SIZE = [0,0].pack(RTATTR_PACK).bytesize #:nodoc:

    def self.inherited(subclass) #:nodoc:
      super
      subclass.const_set(:RTATTRS, {})
    end

    def self.rtattr(name, code, type=nil, opt={})
      info = TYPE_INFO[type]
      self::RTATTRS[code] = [name, info && info[:pattern]]
      define_method name do
        @attrs.fetch name
      end
      define_method "#{name}=" do |val|
        @attrs.store name, val
      end
    end

    def self.attr_offset #:nodoc:
      @attr_offset ||= Message.align(new.to_s.bytesize)
    end
    
    def to_s
      data = super
      self.class::RTATTRS.each do |code, (name, pattern)|
        if val = @attrs[name]
          Message.pad(data)
          val = Array(val).pack(pattern) if pattern
          data << [val.bytesize+RTATTR_SIZE, code].pack(RTATTR_PACK) << val
        end
      end
      data
    end
    
    def self.parse(data)
      res = super
      ptr = attr_offset
      while ptr < data.bytesize
        raise "Truncated rtattr header!" if ptr + RTATTR_SIZE > data.bytesize
        len, code = data[ptr, RTATTR_SIZE].unpack(RTATTR_PACK)
        raise "Truncated rtattr body!" if ptr + len > data.bytesize
        raise "Invalid rtattr len!" if len < RTATTR_SIZE
        res._add_attr(code, data[ptr+RTATTR_SIZE, len-RTATTR_SIZE])
        ptr = Message.align(ptr + len)
      end
      res
    end
    
    def _add_attr(code, val) # :nodoc:
      name, pattern = self.class::RTATTRS[code]
      if name
        if pattern
          val = val.unpack(pattern)
          val = val.first if val.size == 1
        end
        warn "Duplicate attribute #{name} (#{code}): #{@attrs[name].inspect} -> #{val.inspect}" if @attrs[name]
        @attrs[name] = val
      else
        warn "Unknown attribute #{code}, value #{val.inspect}"
        @attrs[code] = val
      end
    end
  end

  class Link < RtattrMessage
    code RTM_NEWLINK, RTM_DELLINK, RTM_GETLINK
    field :family, :uchar
    field :pad, :uchar
    field :type, :ushort
    field :index, :int
    field :flags, :uint
    field :change, :uint
    rtattr :address, IFLA_ADDRESS
    rtattr :broadcast, IFLA_BROADCAST
    rtattr :ifname, IFLA_IFNAME, :cstring
    rtattr :mtu, IFLA_MTU, :uint32
    rtattr :link, IFLA_LINK, :int32
    rtattr :qdisc, IFLA_QDISC, :cstring
    rtattr :stats, IFLA_STATS, :stats32
    rtattr :cost, IFLA_COST
    rtattr :master, IFLA_MASTER
    rtattr :wireless, IFLA_WIRELESS
    rtattr :protinfo, IFLA_PROTINFO
    rtattr :txqlen, IFLA_TXQLEN, :uint32
    rtattr :map, IFLA_MAP
    rtattr :weight, IFLA_WEIGHT
    rtattr :operstate, IFLA_OPERSTATE, :uchar
    rtattr :linkmode, IFLA_LINKMODE, :uchar
    rtattr :linkinfo, IFLA_LINKINFO
    rtattr :net_ns_pid, IFLA_NET_NS_PID
    rtattr :ifalias, IFLA_IFALIAS
    rtattr :num_vf, IFLA_NUM_VF, :uint32
    rtattr :vfinfo_list, IFLA_VFINFO_LIST
    rtattr :stats64, IFLA_STATS64, :stats64
    rtattr :vf_ports, IFLA_VF_PORTS
    rtattr :port_self, IFLA_PORT_SELF
  end

  class Addr < RtattrMessage
    code RTM_NEWADDR, RTM_DELADDR, RTM_GETADDR
    field :family, :uchar
    field :prefixlen, :uchar
    field :flags, :uchar
    field :scope, :uchar
    field :index, :int
    rtattr :address, IFA_ADDRESS
    rtattr :local, IFA_LOCAL
    rtattr :label, IFA_LABEL, :cstring
    rtattr :broadcast, IFA_BROADCAST
    rtattr :anycase, IFA_ANYCAST
    rtattr :cacheinfo, IFA_CACHEINFO
    rtattr :multicast, IFA_MULTICAST
  end

  class Route < RtattrMessage
    code RTM_NEWROUTE, RTM_DELROUTE, RTM_GETROUTE
    field :family, :uchar
    field :dst_len, :uchar
    field :src_len, :uchar
    field :tos, :uchar
    field :table, :uchar
    field :protocol, :uchar
    field :scope, :uchar
    field :type, :uchar
    field :flags, :uint
    rtattr :dst, RTA_DST
    rtattr :src, RTA_SRC
    rtattr :iif, RTA_IIF, :uint32
    rtattr :oif, RTA_OIF, :uint32
    rtattr :gateway, RTA_GATEWAY
    rtattr :priority, RTA_PRIORITY, :uint32
    rtattr :prefsrc, RTA_PREFSRC
    rtattr :metrics, RTA_METRICS
    rtattr :multipath, RTA_MULTIPATH
    rtattr :flow, RTA_FLOW
    rtattr :cacheinfo, RTA_CACHEINFO
    rtattr :table2, RTA_TABLE, :uint32   # NOTE: table in two places!
  end
end
