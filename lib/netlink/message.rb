require 'netlink/constants'

module Netlink
  # Base class for Netlink messages
  class Message
    # Map of numeric message type code => message class
    CODE_TO_MESSAGE = {}

    # You can initialize a message from a Hash or from another
    # instance of itself.
    #
    #   class Foo < Message
    #     field :foo, "C", 0xff
    #     field :bar, "L", 0
    #   end
    #   msg = Foo.new(:bar => 123)  # or ("bar" => 123)
    #   msg2 = Foo.new(msg)
    #   msg3 = Foo.new(:qux => 999) # error, no method qux=
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
    
    # Define a field for this message, which creates accessor methods. The
    # "pattern" is the Array#pack or String#unpack code to extract this field.    
    def self.field(name, pattern, default=nil, opt={})
      self::FIELDS << name
      self::FORMAT << pattern
      self::DEFAULTS[name] = default
      define_method name do
        @attrs.fetch name
      end
      define_method "#{name}=" do |val|
        @attrs.store name, val
      end
    end

    def self.uchar(name, *args);	field name, "C", 0, *args; end
    def self.uint16(name, *args);	field name, "S", 0, *args; end
    def self.uint32(name, *args);	field name, "L", 0, *args; end
    def self.char(name, *args);		field name, "c", 0, *args; end
    def self.int16(name, *args);	field name, "s", 0, *args; end
    def self.int32(name, *args);	field name, "l", 0, *args; end
    def self.ushort(name, *args);	field name, "S_", 0, *args; end
    def self.uint(name, *args);		field name, "I", 0, *args; end
    def self.ulong(name, *args);	field name, "L_", 0, *args; end
    def self.short(name, *args);	field name, "s_", 0, *args; end
    def self.int(name, *args);		field name, "i", 0, *args; end
    def self.long(name, *args);		field name, "l_", 0, *args; end
    
    # Returns the packed binary representation of this message (without
    # header, and not padded to NLMSG_ALIGNTO bytes)    
    def to_s
      self.class::FIELDS.map { |key| self[key] }.pack(self.class::FORMAT)
    end

    def inspect
      "#<#{self.class} #{@attrs.inspect}>"
    end
    
    # Convert a binary representation of this message into an object instance
    def self.parse(str)
      res = new
      str.unpack(self::FORMAT).zip(self::FIELDS).each do |val, key|
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

  class Link < Message
    code RTM_NEWLINK, RTM_DELLINK, RTM_GETLINK
    uchar :family
    uchar :pad
    ushort :type
    int :index
    uint :flags
    uint :change
  end

  class Addr < Message
    code RTM_NEWADDR, RTM_DELADDR, RTM_GETADDR
    uchar :family
    uchar :prefixlen
    uchar :flags
    uchar :scope
    int :index
  end

  class Route < Message
    code RTM_NEWROUTE, RTM_DELROUTE, RTM_GETROUTE
    uchar :family
    uchar :dst_len
    uchar :src_len
    uchar :tos
    uchar :table
    uchar :protocol
    uchar :scope
    uchar :type
    uint :flags
  end
end
