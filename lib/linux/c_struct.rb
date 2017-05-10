module Linux

# This class allows defining of C-style structures, and converting
# object instances to and from a packed binary representation.
#
# A new structure is created by subclassing CStruct, and then using the
# 'field' metaprogramming macro to define each field:
#
#   class Foo < Linux::CStruct
#     field :bar, :char
#     field :baz, :long
#
#     # custom packing
#     field :qux, :pattern => "Z16", :default => EMPTY_STRING
#
#     # user-defined types
#     define_type :str16, :pattern => "Z16", :default => EMPTY_STRING
#     field :qux2, :str16
#     field :qux3, :str16
#   end
#
# You can then instantiate the structure by calling 'new'. You may pass in
# a hash of values to initialize the structure.
#
#   msg = Foo.new(:bar => 123)
#   msg.bar = 456               # accessor methods
#   str = msg.to_str            # convert to binary
#   msg2 = Foo.parse(str)       # convert from binary
#   msg2 = Foo.new(msg)         # copy an existing object
class CStruct
  EMPTY_STRING = "".freeze #:nodoc:
  EMPTY_ARRAY  = [].freeze #:nodoc:

  TYPE_INFO = {} #:nodoc

  # The size of the structure (in bytes)
  def self.bytesize
    @bytesize
  end

  # Define a new type for use with 'field'. You supply the
  # symbolic name for the type, and a set of options.
  #    :pattern => "str"    # format string for Array#pack / String#unpack
  #    :default => val      # default (if not 0)
  #    :size => 16          # size of this entry
  #    :align => 4          # align to 4-byte boundary (must be power-of-two)
  #    :align => true       # align to [size]-byte boundary
  #
  # If you do not specify :size then it is calculated by packing an
  # instance of the default value.
  def self.define_type(name, opt)
    TYPE_INFO[name] = opt
  end

  # Return a type info hash given a type id. Raises IndexError if not found.
  def self.find_type(type)
    case type
    when nil, Hash
      type
    else
      TYPE_INFO.fetch(type)
    end
  end

  define_type :uchar,   :pattern => "C"
  define_type :uint16,  :pattern => "S",  :align => true
  define_type :uint32,  :pattern => "L",  :align => true
  define_type :uint64,  :pattern => "Q",  :align => true
  define_type :char,    :pattern => "c"
  define_type :int16,   :pattern => "s",  :align => true
  define_type :int32,   :pattern => "l",  :align => true
  define_type :int64,   :pattern => "q",  :align => true
  define_type :ushort,  :pattern => "S_", :align => true
  define_type :uint,    :pattern => "I",  :align => true
  define_type :ulong,   :pattern => "L_", :align => true
  define_type :short,   :pattern => "s_", :align => true
  define_type :int,     :pattern => "i",  :align => true
  define_type :long,    :pattern => "l_", :align => true
  define_type :ns,      :pattern => "n",  :align => true
  define_type :nl,      :pattern => "N",  :align => true

  begin
    require 'linux/c_struct_sizeof_size_t.rb'
  rescue LoadError
    warn "netlinkrb: Assuming size_t is a long unsigned int." if $DEBUG
    SIZEOF_SIZE_T = [0].pack("L_").size
  end

  define_type :size_t,
    case SIZEOF_SIZE_T
    when 8
      {:pattern => "Q", :align => true}
    when 4
      {:pattern => "L", :align => true}
    else
      raise "Bad size_t (#{SIZEOF_SIZE_T.inspect})"
    end
  # these can be used at end of structure only
  define_type :binary,  :pattern => "a*", :default => EMPTY_STRING
  # cstring has \x00 terminator when sent over wire
  define_type :cstring, :pattern => "Z*", :default => EMPTY_STRING

  def initialize(h=nil)
    if h.instance_of?(self.class)
      @attrs = h.to_hash.dup
    else
      @attrs = {}
      h.each { |k,v| self[k] = v } if h
    end
  end

  # This hook is called after unpacking from binary, and can be used
  # for fixing up the data
  def after_parse
  end

  def to_hash
    @attrs
  end

  def each(&blk)
    @attrs.each(&blk)
  end

  # Set a field by name. Currently can use either symbol or string as key.
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
    subclass.instance_variable_set(:@bytesize, 0)
  end

  # Define a field for this message, which creates accessor methods and
  # sets up data required to pack and unpack the structure.
  #    field :foo, :uchar
  #    field :foo, :uchar, :default=>0xff    # use this default value
  def self.field(name, type, opt={})
    info = find_type(type)
    pattern = info[:pattern]
    default = opt.fetch(:default) { info.fetch(:default, 0) }

    # Apply padding for structure alignment if necessary
    size = info[:size] || [default].pack(pattern).bytesize
    if align = (opt[:align] || info[:align])
      align = size if align == true
      field_pad alignto(@bytesize, align) - @bytesize
    end
    @bytesize += size

    self::FIELDS << name
    self::FORMAT << pattern
    self::DEFAULTS[name] = default

    define_method name do
      @attrs[name]
    end
    define_method "#{name}=" do |val|
      @attrs.store name, val
    end
  end

  # Skip pad byte(s) - default 1
  def self.field_pad(count=1)
    if count > 0
      self::FORMAT << "x#{count}"
      @bytesize += count
    end
  end

  # Returns the packed binary representation of this structure
  def to_str
    self.class::FIELDS.map { |key| self[key] || self.class::DEFAULTS[key] }.pack(self.class::FORMAT)
  end

  def inspect
    "#<#{self.class} #{@attrs.inspect}>"
  end

  # Convert a binary representation of this structure into an object instance.
  # If a block is given, the object is yielded to that block. Finally the
  # after_parse hook is called.
  def self.parse(data, obj=new)
    data.unpack(self::FORMAT).zip(self::FIELDS).each do |val, key|
      obj[key] = val
    end
    yield obj if block_given?
    obj.after_parse
    obj
  end

  # Round up a number to multiple of m, where m is a power of two
  def self.alignto(val, m)
    (val + (m-1)) & ~(m-1)
  end
end
end # module Linux
