require 'linux/iptables'
require 'ipaddr'

module Linux
  #-
  # Definitions mainly from linux/netfilter_ipv4/ip_tables.h
  #+

  # struct ipt_getinfo
  class IPTGetInfo < FFI::AStruct
    layout :name, [:char, IPT_TABLE_MAXNAMELEN],
      :valid_hooks, :uint,
      :hook_entry, [:uint, NF_INET_NUMHOOKS],
      :underflow, [:uint, NF_INET_NUMHOOKS],
      :num_entries, :uint,
      :size, :uint
  end

  class IPTIP < FFI::AStruct
    layout :src, :int32,  # FIXME: needs ntohl
      :dst, :int32,
      :smsk, :int32,
      :dmsk, :int32,
      :iniface, [:char, IFNAMSIZ],
      :outiface, [:char, IFNAMSIZ],
      :iniface_mask, [:uchar, IFNAMSIZ],
      :outiface_mask, [:uchar, IFNAMSIZ],
      :proto, :uint16,
      :flags, :uint8,
      :invflags, :uint8
  end

  # struct xt_counters (netfilter/x_tables.h)
  class XTCounters < FFI::AStruct
    layout :pcnt, :uint64,
      :bcnt, :uint64
  end
    
  # struct ipt_entry
  class IPTEntry < FFI::AStruct
    layout :ip, IPTIP,
      :nfcache, :uint,
      :target_offset, :uint16,	# size of ipt_entry + matches
      :next_offset, :uint16,	# size of ipt_entry + matches + target
      :comefrom, :uint,
      :counters, XTCounters,
      :elems, [:uchar, 1]	# should be [:uchar, 0]
  end

  # struct ipt_get_entries
  class IPTGetEntries < FFI::AStruct
    layout :name, [:uchar, IPT_TABLE_MAXNAMELEN],
      :size, :uint,
      :entrytable, [IPTEntry, 1]	# should be [IPTEntry, 0]
  end

  # Class for handling iptables. Note that this doesn't actually use
  # Netlink at all :-(
  class Iptables4 < Iptables
    PROC_TABLES		= "/proc/net/ip_tables_names"
    PROC_TARGETS	= "/proc/net/ip_tables_targets"
    PROC_MATCHES	= "/proc/net/ip_tables_matches"

    TABLE_MAXNAMELEN	= IPT_TABLE_MAXNAMELEN
    TC_AF		= Socket::AF_INET
    TC_IPPROTO		= Socket::IPPROTO_IP
    SO_GET_INFO		= IPT_SO_GET_INFO
    SO_GET_ENTRIES	= IPT_SO_GET_ENTRIES
    STRUCT_ENTRY	= IPTEntry
    STRUCT_GETINFO	= IPTGetInfo
    STRUCT_GET_ENTRIES	= IPTGetEntries
    # This is a frig because of [1] instead of [0] above
    STRUCT_GET_ENTRIES_SIZE = IPTGetEntries.offset_of(:entrytable)
  end
end

if __FILE__ == $0
  require 'pp'
  pp Linux::Iptables4.tables
  pp Linux::Iptables4.table("filter").rules
end
