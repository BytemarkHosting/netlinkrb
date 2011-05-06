require 'linux/iptables'

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
    field :entrytable, :binary, :align=>1.size   # struct ipt_entry entrytable[0]
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
    field :nfcache, :uint
    field :target_offset, :uint16	# size of ipt_entry + matches
    field :next_offset, :uint16		# size of ipt_entry + matches + target
    field :comefrom, :uint
    ### struct xt_counters
    field :packet_count, :uint64, :align => 8
    field :byte_count, :uint64
    ###
    field :elems, :binary   # matches (if any), then the target

    def after_parse
      self.src = src == 0 ? nil : IPAddr.new(src, Socket::AF_INET)
      self.dst = dst == 0 ? nil : IPAddr.new(dst, Socket::AF_INET)
      self.smsk = smsk == 0 ? nil : IPAddr.new(smsk, Socket::AF_INET)
      self.dmsk = dmsk == 0 ? nil : IPAddr.new(dmsk, Socket::AF_INET)
    end
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
  end
end

if __FILE__ == $0
  require 'pp'
  pp Linux::Iptables4.tables
  pp Linux::Iptables4.table("filter").rules
end
