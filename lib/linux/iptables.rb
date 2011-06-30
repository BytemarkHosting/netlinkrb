require 'socket'
require 'linux/constants'

begin
  require 'ffi'
rescue LoadError
  require('rubygems') ? retry : raise
end


# Good things about FFI::Struct:
# - robust pre-existing code
# - good handling of nested structures and nested arrays
# Bad things about FFI::Struct:
# - no Hash initialization:  MyStruct.new(:foo=>1, :bar=>2)  [*]
# - no accessor methods      m.foo = 1  [*]
# - can't do zero size array at end of struct: layout :foo, [Foo, 0]
# - no network-order fields? (in_addr)
# - no decent inspect [*]
# [*] Fixed below in FFI::AStruct

class FFI::AStruct < FFI::Struct
  # https://github.com/ffi/ffi/issues/102
  def inspect
    res = "#<#{self.class}"
    members.zip(values).each do |m,v|
      res << " #{m}=#{v.inspect}"
    end
    res << ">"
  end

  # https://github.com/ffi/ffi/issues/106
  def initialize(*args)
    if args.first.is_a? Hash
      super(nil, *args[1..-1])
      src.each { |k,v| self[k] = v }
    else
      super
    end
  end

  # https://github.com/ffi/ffi/issues/107
  def self.layout(*fields)
    super
    fields.each_slice(2) do |name,type|
      # Structure building is screwed up if there's a 'size' member!
      next if instance_methods.find { |m| m.to_sym == name }
      define_method name do
        self[name]
      end
      define_method "#{name}=" do |v|
        self[name] = v
      end
    end
  end
end

# https://github.com/ffi/ffi/issues/102
class FFI::StructLayout::CharArray
  def inspect
    to_s.inspect
  end
end

module Linux
  module Ext
    extend FFI::Library
    ffi_lib FFI::Library::LIBC
    attach_function :getsockopt, [:int, :int, :int, :buffer_inout, :buffer_inout], :int
  end

  # *** THIS CODE IS INCOMPLETE ***
  #
  # Virtual base class for handling iptables. You should invoke either
  # Iptables4 or Iptables6 as appropriate.
  #
  # (Mirrors the structure of iptables libiptc/libiptc.c, included by
  # libip4tc.c and libip6tc.c)
  #
  #    filter = Linux::Iptables4.table("filter")
  class Iptables
    def self.inherited(subclass) #:nodoc:
      subclass.instance_variable_set(:@tables, {})
    end
    
    def self.socket
      @socket ||= Socket.new(self::TC_AF, Socket::SOCK_RAW, Socket::IPPROTO_RAW)
    end
    
    def self.table(tablename = "filter")
      @tables[tablename] ||= new(tablename, socket)
    end
    
    def self.tables
      proc_read(self::PROC_TABLES)
    end
    
    def self.targets
      proc_read(self::PROC_TARGETS)
    end
    
    def self.matches
      proc_read(self::PROC_MATCHES)
    end
    
    def self.proc_read(filename)
      File.readlines(filename).each { |x| x.chomp! }
    end

    def initialize(name, socket)
      raise "Invalid table name" if name.bytesize > self.class::TABLE_MAXNAMELEN
      @name = name
      @socket = socket
      reload
    end

    def rules
      @rules
    end
    
    def getsockopt(level, optname, buf)
      buflen = FFI::Buffer.new :socklen_t
      if buflen.size == 4
        buflen.put_uint32(0, buf.size)
      elsif buflen.size == 8
        buflen.put_uint64(0, buf.size)
      else
        raise "Unexpected buflen length: #{buflen.size}"
      end
      res = Ext.getsockopt(@socket.fileno, level, optname, buf, buflen)
      raise "getsockopt error: #{res}" if res < 0  # FIXME: get errno?
      res   # unlike Ruby's getsockopt, we return the length, not the buf
    end
    
    def reload
      info = IPTGetInfo.new
      info[:name] = @name
      getsockopt(self.class::TC_IPPROTO, self.class::SO_GET_INFO, info)
      #warn "valid_hooks=0x%08x, num_entries=%d, size=%d" % [info[:valid_hooks], info[:num_entries], info[:size]]

      init = self.class::STRUCT_GET_ENTRIES.new
      init[:name] = @name
      init[:size] = info[:size]
      buf2 = FFI::MemoryPointer.new(self.class::STRUCT_GET_ENTRIES_SIZE + info[:size])
      buf2.put_bytes(0, init.pointer.get_bytes(0, self.class::STRUCT_GET_ENTRIES_SIZE))
      getsockopt(self.class::TC_IPPROTO, self.class::SO_GET_ENTRIES, buf2)

      res = []
      offset = self.class::STRUCT_GET_ENTRIES_SIZE
      limit = offset + info[:size]
      while offset < limit
        res << self.class::STRUCT_ENTRY.new(buf2 + offset)
        offset += res.last[:next_offset]
      end
      raise "Error parsing rules: got #{res.size} instead of #{info[:num_entries]}" if res.size != info[:num_entries]
      @rules = res
    end
  end
end
