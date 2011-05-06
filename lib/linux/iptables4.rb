require 'socket'
require 'linux/constants'
require 'linux/c_struct'
require 'linux/netlink/message'  # just for :dev_name type

module Linux
  #-
  # Definitions mainly from linux/netfilter_ipv4/ip_tables.h
  #+

  # struct ipt_getinfo
  class IPTGetInfo < CStruct
    field :name, :pattern=>"Z#{IPT_TABLE_MAXNAMELEN}", :default=>EMPTY_STRING
    field :valid_hooks, :int
    #field :hook_entry, :pattern=>"I#{NF_INET_NUMHOOKS}", :default=>[0]*NF_INET_NUMHOOKS
    #field :underflow, :pattern=>"I#{NF_INET_NUMHOOKS}", :default=>[0]*NF_INET_NUMHOOKS
    field :hook_entry, :pattern=>"a#{NF_INET_NUMHOOKS*4}", :default=>EMPTY_STRING
    field :underflow, :pattern=>"a#{NF_INET_NUMHOOKS*4}", :default=>EMPTY_STRING
    field :num_entries, :int
    field :size, :int
  end

  # struct ipt_get_entries
  class IPTGetEntries < CStruct
    field :name, :pattern=>"Z#{IPT_TABLE_MAXNAMELEN}", :default=>EMPTY_STRING
    field :size, :uint
    #field :entrytable, :pattern=>
    field :entrytable, :binary   # struct ipt_entry entrytable[]
  end
  
  # struct ipt_entry
  class IPTEntry < CStruct
    #### struct ipt_ip
    field :src, :nl   # struct in_addr
    field :dst, :nl
    field :smsk, :nl
    field :dmsk, :nl
    field :iniface, :dev_name
    field :outiface, :dev_name
    field :iniface_mask, :dev_name
    field :outiface_mask, :dev_name
    field :proto, :uint16
    field :flags, :uchar
    field :invflags, :uchar
    ####
    field :nfcache, :int
    field :target_offset, :uint16
    field :next_offset, :uint16
    field :comefrom, :uint
    field :packet_count, :uint64
    field :byte_count, :uint64
    field :elems, :binary
  end

  # Class for handling iptables. Note that this doesn't actually use
  # Netlink at all :-(
  class Iptables4
    TC_AF = Socket::AF_INET
    TC_IPPROTO = Socket::IPPROTO_IP
    SO_GET_INFO = IPT_SO_GET_INFO
    STRUCT_GETINFO = IPTGetInfo
    STRUCT_GET_ENTRIES = IPTGetEntries

    def initialize(tablename = "filter")
      @socket = Socket.new(TC_AF, Socket::SOCK_RAW, Socket::IPPROTO_RAW)
      info = STRUCT_GETINFO.new(:name => tablename)
      # FIXME: ruby won't let us pass structure to getsockopt!!
      @socket.getsockopt(TC_IPPROTO, SO_GET_INFO, info)
      warn "valid_hooks=0x%08x, num_entries=%d, size=%d" % [info.valid_hooks, info.size, info.num_entries]
    end
  end
end

if __FILE__ == $0
  iptables = Linux::Iptables4.new
end
