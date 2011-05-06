require 'socket'
require 'linux/constants'
require 'linux/c_struct'
require 'linux/netlink/message'  # just for :dev_name type

module Linux
  module Ext
    require 'ffi'
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
  #
  # TODO: should we use ffi's structures instead of CStruct?
  # We have to use ffi anyway, until ruby getsockopt supports buffer passing.
  # http://redmine.ruby-lang.org/issues/4645
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
      if buflen.length == 4
        buflen.put_uint32(0, buf.length)
      elsif buflen.length == 8
        buflen.put_uint64(0, buf.length)
      else
        raise "Unexpected buflen length: #{buflen.length}"
      end
      res = Ext.getsockopt(@socket.fileno, level, optname, buf, buflen)
      raise "getsockopt error: #{res}" if res < 0  # FIXME: get errno?
      buf.get_bytes(0, buflen.length == 4 ? buflen.get_uint32(0) : buflen.get_uint64(0))
    end
    
    def reload
      buf = FFI::Buffer.new IPTGetInfo.bytesize
      buf.put_string(0, @name)
      info = self.class::STRUCT_GETINFO.parse(getsockopt(self.class::TC_IPPROTO, self.class::SO_GET_INFO, buf))
      #warn "valid_hooks=0x%08x, num_entries=%d, size=%d" % [info.valid_hooks, info.num_entries, info.size]

      buf2 = FFI::Buffer.new(self.class::STRUCT_GET_ENTRIES.bytesize + info.size)
      buf2.put_bytes(0, self.class::STRUCT_GET_ENTRIES.new(:name=>@name, :size=>info.size).to_str)
      getsockopt(self.class::TC_IPPROTO, self.class::SO_GET_ENTRIES, buf2)

      res = []
      ptr = self.class::STRUCT_GET_ENTRIES.bytesize
      limit = ptr + info.size
      while ptr < limit
        res << self.class::STRUCT_ENTRY.parse(buf2.get_bytes(ptr, self.class::STRUCT_ENTRY.bytesize))
        ptr += res.last.next_offset
      end
      raise "Error parsing rules: got #{res.size} instead of #{info.num_entries}" if res.size != info.num_entries
      @rules = res
    end
  end
end
