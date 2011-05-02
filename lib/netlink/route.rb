# This file implements the messages and methods for the NETLINK_ROUTE protocol

require 'netlink/nlsocket'
require 'netlink/message'

module Netlink
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

  # struct ifmap
  IFMap = Struct.new :mem_start, :mem_end, :base_addr, :irq, :dma, :port

  # struct ifinfomsg
  class IFInfo < RtattrMessage
    code RTM_NEWLINK, RTM_DELLINK, RTM_GETLINK

    field :family, :uchar			# Socket::AF_*
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
    rtattr :stats32, IFLA_STATS,
        :pack   => lambda { |val,obj| val.to_a.pack("L23") },
        :unpack => lambda { |str,obj| LinkStats.new(*(str.unpack("L23"))) }
    rtattr :cost, IFLA_COST
    rtattr :master, IFLA_MASTER, :uint32
    rtattr :wireless, IFLA_WIRELESS
    rtattr :protinfo, IFLA_PROTINFO, :uchar
    rtattr :txqlen, IFLA_TXQLEN, :uint32
    IFMAP_PACK = "QQQSCC".freeze #:nodoc:
    rtattr :map, IFLA_MAP,
        :pack   => lambda { |val,obj| val.to_a.pack(IFMAP_PACK) },
        :unpack => lambda { |str,obj| IFMap.new(*(str.unpack(IFMAP_PACK))) }
    rtattr :weight, IFLA_WEIGHT, :uint32
    rtattr :operstate, IFLA_OPERSTATE, :uchar
    rtattr :linkmode, IFLA_LINKMODE, :uchar
    rtattr :linkinfo, IFLA_LINKINFO # nested
    rtattr :net_ns_pid, IFLA_NET_NS_PID, :uint32
    rtattr :ifalias, IFLA_IFALIAS, :cstring
    rtattr :num_vf, IFLA_NUM_VF, :uint32
    rtattr :vfinfo_list, IFLA_VFINFO_LIST
    rtattr :stats64, IFLA_STATS64,
        :pack   => lambda { |val,obj| val.to_a.pack("Q23") },
        :unpack => lambda { |str,obj| LinkStats.new(*(str.unpack("Q23"))) }
    rtattr :vf_ports, IFLA_VF_PORTS
    rtattr :port_self, IFLA_PORT_SELF
    
    # Return the best stats available (64bit or 32bit)
    def stats
      stats64 || stats32
    end
  end

  # struct ifa_cacheinfo
  IFACacheInfo = Struct.new :prefered, :valid, :cstamp, :tstamp

  # struct ifaddrmsg
  class IFAddr < RtattrMessage
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
    rtattr :cacheinfo, IFA_CACHEINFO,
        :pack   => lambda { |val,obj| val.to_a.pack("L*") },
        :unpack => lambda { |str,obj| IFACacheInfo.new(*(str.unpack("L*"))) }
    rtattr :multicast, IFA_MULTICAST, :l3addr
  end

  # struct rta_cacheinfo
  RTACacheInfo = Struct.new :clntref, :lastuse, :expires, :error, :used, :id, :ts, :tsage

  # struct rtmsg
  class RT < RtattrMessage
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
    # Route metrics are themselves packed using the rtattr format.
    # In the kernel, the dst.metrics structure is an array of u32.
    METRIC_PACK = "SSL".freeze #:nodoc:
    METRIC_SIZE = [0,0,0].pack(METRIC_PACK).bytesize #:nodoc:
    rtattr :metrics, RTA_METRICS,		# {RTAX_* => Integer}
        :pack   => lambda { |metrics,obj|
          metrics.map { |code,val| [METRIC_SIZE,code,val].pack(METRIC_PACK) }.join
        },
        :unpack => lambda { |str,obj|
          res = {}
          RtattrMessage.unpack_rtattr(str) { |code,val| res[code] = val.unpack("L").first }
          res
        }
    rtattr :multipath, RTA_MULTIPATH
    rtattr :flow, RTA_FLOW
    rtattr :cacheinfo, RTA_CACHEINFO,
        :pack   => lambda { |val,obj| val.to_a.pack("L*") },
        :unpack => lambda { |str,obj| RTACacheInfo.new(*(str.unpack("L*"))) }
    rtattr :table2, RTA_TABLE, :uint32   # NOTE: table in two places!
  end

  module Route
    # This class formats and receives messages using NETLINK_ROUTE protocol
    class Socket < NLSocket
      def initialize(opt={})
        super(opt.merge(:protocol => Netlink::NETLINK_ROUTE))
        clear_cache
      end

      # Download a list of links (interfaces). Either returns an array of
      # Netlink::IFInfo objects, or yields them to the supplied block.
      #
      #   res = nl.read_links
      #   p res
      #   [#<Netlink::IFInfo {:family=>0, :type=>772, :index=>1,
      #    :flags=>65609, :change=>0, :ifname=>"lo", :txqlen=>0, :operstate=>0,
      #    :linkmode=>0, :mtu=>16436, :qdisc=>"noqueue", :map=>"...",
      #    :address=>"\x00\x00\x00\x00\x00\x00", :broadcast=>"\x00\x00\x00\x00\x00\x00",
      #    :stats32=>#<struct Netlink::LinkStats rx_packets=22, ...>,
      #    :stats64=>#<struct Netlink::LinkStats rx_packets=22, ...>}>, ...]
      def read_links(opt=nil, &blk)
        send_request RTM_GETLINK, IFInfo.new(opt),
                     NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST
        receive_until_done(RTM_NEWLINK, &blk)
      end

      # Download a list of routes. Either returns an array of
      # Netlink::RT objects, or yields them to the supplied block.
      #
      # A hash of kernel options may be supplied, but you might also have
      # to perform your own filtering. e.g.
      #   rt.read_routes(:family=>Socket::AF_INET)           # works
      #   rt.read_routes(:protocol=>Netlink::RTPROT_STATIC)  # ignored
      #
      #   res = nl.read_routes(:family => Socket::AF_INET)
      #   p res
      #   [#<Netlink::RT {:family=>2, :dst_len=>32, :src_len=>0, :tos=>0,
      #    :table=>255, :protocol=>2, :scope=>253, :type=>3, :flags=>0, :table2=>255,
      #    :dst=>#<IPAddr: IPv4:127.255.255.255/255.255.255.255>,
      #    :prefsrc=>#<IPAddr: IPv4:127.0.0.1/255.255.255.255>, :oif=>1}>, ...]
      #
      # Note that not all attributes will always be present. In particular,
      # a defaultroute (dst_len=0) misses out the dst address completely:
      #
      #   [#<Netlink::RT {:family=>2, :dst_len=>0, :src_len=>0, :tos=>0,
      #    :table=>254, :protocol=>4, :scope=>0, :type=>1, :flags=>0, :table2=>254,
      #    :gateway=>#<IPAddr: IPv4:10.69.255.253/255.255.255.255>, :oif=>2}>, ...]
      def read_routes(opt=nil, &blk)
        send_request RTM_GETROUTE, RT.new(opt),
                     NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST
        receive_until_done(RTM_NEWROUTE, &blk)
      end
      
      # Download a list of link addresses. Either returns an array of
      # Netlink::IFAddr objects, or yields them to the supplied block.
      # You will need to use the 'index' to cross reference to the interface.
      #
      # A hash of kernel options may be supplied, but likely only :family
      # is honoured.
      #
      #   res = nl.read_addrs(:family => Socket::AF_INET)
      #   p res
      #   [#<Netlink::IFAddr {:family=>2, :prefixlen=>8, :flags=>128, :scope=>254,
      #    :index=>1, :address=>#<IPAddr: IPv4:127.0.0.1/255.255.255.255>,
      #    :local=>#<IPAddr: IPv4:127.0.0.1/255.255.255.255>, :label=>"lo"}>, ...]
      def read_addrs(opt=nil, &blk)
        send_request RTM_GETADDR, IFAddr.new(opt),
                     NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST
        receive_until_done(RTM_NEWADDR, &blk)
      end

      # Download a list of addresses, grouped as {index=>[addr,addr], index=>[addr,addr]}
      def read_addrs_by_ifindex(opt=nil)
        res = read_addrs(opt).group_by { |obj| obj.index }
        res.default = EMPTY_ARRAY
        res
      end

      # Add an IP address to an interface
      #
      #    require 'netlink/route'
      #    rt = Netlink::Route::Socket.new
      #    rt.add_ipaddr(:index=>"eth0", :local=>"1.2.3.4", :prefixlen=>24)
      def add_addr(opt)
        ipaddr_modify(RTM_NEWADDR, NLM_F_CREATE|NLM_F_EXCL, opt)
      end

      def change_addr(opt)
        ipaddr_modify(RTM_NEWADDR, NLM_F_REPLACE, opt)
      end
      
      def replace_addr(opt)
        ipaddr_modify(RTM_NEWADDR, NLM_F_CREATE|NLM_F_REPLACE, opt)
      end
      
      # Delete an IP address from an interface. Pass in either a hash of
      # parameters, or an existing IFAddr object.
      def delete_addr(opt)
        ipaddr_modify(RTM_DELADDR, 0, opt)
      end
      
      def ipaddr_modify(code, flags, msg) #:nodoc:
        msg = IFAddr.new(msg)
        case msg.index
        when nil
          raise "Device index must be specified"
        when String
          msg.index = linkindex(msg.index)
        end
        msg.address ||= msg.local
        # Note: IPAddr doesn't support addresses off the subnet base,
        # so there's no point trying to set msg.prefixlen from the IPAddr mask
        cmd code, msg, flags|NLM_F_REQUEST
        clear_cache
      end
      
      # Clear the memoization cache
      def clear_cache
        @links = nil
        @link = nil
        @addrs = nil
        @routes = nil
      end
      
      # Return the memoized interface table as a flat array, suitable for
      # iteration. e.g.
      #    rt.links.each { |link| puts link.ifname }
      def links
        @links ||= read_links
      end

      # Return the memoized interface table, keyed by both ifname and ifindex. e.g.
      #    puts rt.link["eth0"].index
      #    puts rt.link[1].ifname
      def link
        @link ||= (
          h = {}
          links.each { |link| h[link.index] = h[link.ifname] = link }
          h
        )
      end
      
      # Convert a link index to a (String) name, or nil.
      #
      #    rt.routes[Socket::AF_INET].each do |route|
      #      puts "iif=#{rt.linkname(route.iif)}"
      #      puts "oif=#{rt.linkname(route.oif)}"
      #    end
      def linkname(x)
        link[x] && link[x].ifname
      end
      
      # Convert a link name to an (Integer) index, or nil.
      def linkindex(x)
        link[x] && link[x].index
      end
      
      # Return the memoized address table, keyed by interface name and
      # address family, containing an array of addresses for each
      # interface/family combination. i.e.
      #
      #    # {ifname=>{family=>[addr,addr,...], ...}, ...}
      #    puts rt.addrs["eth0"][Socket::AF_INET][0].address
      #
      # If there are no addresses for a particular family then it will
      # return a (frozen) empty array, to make iteration eaiser.
      def addrs
        @addrs ||= (
          h = {}
          links.each do |link|
            h[link.ifname] = {}
          end
          read_addrs.each do |addr|
            ifname = link[addr.index].ifname
            h[ifname] ||= Hash.new(EMPTY_ARRAY)
            (h[ifname][addr.family] ||= []) << addr
          end
          h
        )
      end

      # Return the memoized route table, keyed by address family, containing
      # an array of routes for each address family. i.e.
      # family combination. i.e.
      #
      #   # {family=>[route,route,...], ...}, ...}
      #   puts rt.routes[Socket::AF_INET].first.dst
      #
      # If there are no routes for a particular family then it will
      # return a (frozen) empty array.
      def routes
        @routes ||= (
          h = {}
          links.each do |link|
            h[link.ifname] = Hash.new(EMPTY_ARRAY)
          end
          read_routes.each do |route|
            (h[route.family] ||= []) << route
          end
          h
        )
      end
    end
  end
end
