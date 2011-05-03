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

    field :family, :uchar
    field :type, :ushort			# ARPHRD_*
    field :index, :int
    field :flags, :uint				# IFF_*
    field :change, :uint, :default=>0xffffffff	# flags to change
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

    # Link kind for special links, e.g. "vlan" or "gre"
    def kind
      linkinfo && linkinfo.kind
    end

    # Set link kind, creating a linkinfo member if necessary. e.g.
    #    i = IFAddr.new
    #    i.kind = "vlan"
    #    i.linkinfo.data = VlanInfo.new(...)
    def kind=(str)
      self.linkinfo ||= LinkInfo.new
      linkinfo.kind = str
    end
    
    def kind?(str)
      kind == str
    end

    def after_parse #:nodoc:
      self.linkinfo = LinkInfo.parse(linkinfo) if linkinfo
    end
  end

  class LinkInfo < RtattrMessage
    rtattr :kind, IFLA_INFO_KIND, :cstring
    rtattr :data, IFLA_INFO_DATA	# rtattr packed, see below
    rtattr :xstats, :IFLA_INFO_XSTATS	# don't know
    
    def after_parse #:nodoc:
      case kind
      when "vlan"
        self.data = VlanInfo.parse(data)
      end
    end
  end

  class VlanFlags < CStruct
    field :flags, :uint32
    field :mask, :uint32, :default => 0xffffffff
  end

  # VLAN information is packed in rtattr format (there is no corresponding 'struct')  
  class VlanInfo < RtattrMessage
    rtattr :id, IFLA_VLAN_ID, :ushort
    rtattr :flags, IFLA_VLAN_FLAGS,
      :unpack => lambda { |str,obj| VlanFlags.parse(str) }
    rtattr :egress_qos, IFLA_VLAN_EGRESS_QOS
    rtattr :ingress_qos, IFLA_VLAN_INGRESS_QOS
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

  module Route
    # This class provides an API for manipulating interfaces and addresses.
    # Since we frequently need to map ifname to ifindex, or vice versa,
    # we keep a memoized list of interfaces. If the interface list changes,
    # you should create a new instance of this object.
    class IFHandler
      def initialize(nlsocket = Netlink::Route::Socket.new)
        @nlsocket = nlsocket
        clear_link_cache
        clear_addr_cache
      end

      def clear_link_cache
        @links = nil
        @linkmap = nil
      end
      
      def clear_addr_cache
        @addrs = nil
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
        @nlsocket.send_request RTM_GETLINK, IFInfo.new(opt),
                     NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST
        @nlsocket.receive_until_done(RTM_NEWLINK, &blk)
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
        @nlsocket.send_request RTM_GETADDR, IFAddr.new(opt),
                     NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST
        @nlsocket.receive_until_done(RTM_NEWADDR, &blk)
      end

      # Download a list of addresses, grouped as {index=>[addr,addr], index=>[addr,addr]}
      def read_addrs_by_ifindex(opt=nil)
        res = read_addrs(opt).group_by { |obj| obj.index }
        res.default = EMPTY_ARRAY
        res
      end

      # Iterate over all interfaces, or interfaces matching the given
      # criteria. Returns an Enumerator if no block given.
      #
      # The full interface list is read once and memoized, so
      # it is efficient to call this method multiple times.
      #
      #    if.links { |x| p x }
      #    ethers = if.links(:type => Netlink::ARPHRD_ETHER).to_a
      #    vlans = if.links(:kind => "vlan").to_a
      #    if.links(:flags => Netlink::IFF_RUNNING)
      #    if.links(:noflags => Netlink::IFF_POINTOPOINT)
      #    if.links(:link => "lo")   # vlan etc attached to this interface
      def links(filter=nil, &blk)
        return to_enum(:links, filter) unless block_given?
        @links ||= read_links
        return @links.each(&blk) unless filter
        filter[:link] = index(filter[:link]) if filter.has_key?(:link)
        @links.each do |l|
          yield l if (!filter[:type] || l.type == filter[:type]) &&
          (!filter[:kind] || l.kind?(filter[:kind])) &&
          (!filter[:flags] || (l.flags & filter[:flags]) == filter[:flags]) &&
          (!filter[:noflags] || (l.flags & filter[:noflags]) == 0) &&
          (!filter[:link] || l.link == filter[:link])
        end
      end
            
      # Return a memoized Hash of interfaces, keyed by both index and name
      def linkmap
        @linkmap ||= (
          h = {}
          links { |link| h[link.index] = h[link.ifname] = link }
          h
        )
      end
      
      # Return details of one interface, given its name or index.
      # Raises exception if unknown value.
      def [](key)
        linkmap.fetch(key)
      end
      
      # Convert an interface index into name string, or nil if the
      # index is nil or empty string. Raises exception for unknown values.
      #
      #    nl = Netlink::Route::Socket.new
      #    nl.rt[Socket::AF_INET].each do |route|
      #      puts "iif=#{nl.if.name(route.iif)}"
      #      puts "oif=#{nl.if.name(route.oif)}"
      #    end
      def name(index)
        return nil if index.nil? || index == 0
        self[index].ifname
      end
      
      # Convert an interface name into index. Returns 0 for nil or empty
      # string. Otherwise raises an exception for unknown values.
      def index(name)
        case name
        when Integer
          name
        when nil, EMPTY_STRING
          0
        else
          self[name].index
        end
      end

      # Add an interface (low-level)
      #
      #    require 'netlink/route'
      #    rt = Netlink::Route::Socket.new
      #    rt.if.add_link(
      #        :link=>"lo",
      #        :linkinfo=>Netlink::LinkInfo.new(
      #            :kind=>"vlan",
      #            :data=>Netlink::VlanInfo.new(
      #                :id=>1234,
      #                :flags => Netlink::VlanFlags.new(
      #                    :flags=>Netlink::VLAN_FLAG_LOOSE_BINDING,
      #                    :mask=>0xffffffff
      #    ))))
                      
      def add_link(opt)
        iplink_modify(RTM_NEWLINK, NLM_F_CREATE|NLM_F_EXCL, opt)
      end

      def change_link(opt)
        iplink_modify(RTM_NEWLINK, NLM_F_REPLACE, opt)
      end
      
      def replace_link(opt)
        iplink_modify(RTM_NEWLINK, NLM_F_CREATE|NLM_F_REPLACE, opt)
      end

      # Delete an existing link. Pass in ifname or index, or options
      # hash {:index=>n}
      def delete_link(opt)
        case opt
        when Integer
          opt = {:index=>opt}
        when String
          opt = {:index=>index(opt)}
        end
        iplink_modify(RTM_DELLINK, 0, opt)
      end
      
      def iplink_modify(code, flags, msg) #:nodoc:
        msg = IFInfo.new(msg)

        if (flags & NLM_F_CREATE) != 0
          raise "Missing :linkinfo" unless msg.linkinfo
          raise "Missing :kind" unless msg.linkinfo.kind
        else
          raise "Missing :index" if msg.index.nil? || msg.index == 0
        end
        
        msg.index = index(msg.index) if msg.index.is_a?(String)
        msg.link  = index(msg.link)  if msg.link.is_a?(String)

        @nlsocket.cmd code, msg, flags|NLM_F_REQUEST
        clear_link_cache
      end

      # Higher-level API to manipulate VLAN interface.
      #    rt.if.add_vlan(
      #      :link=>"lo",
      #      :vlan_id=>1234,
      #      :vlan_flags=>Netlink::VLAN_FLAG_LOOSE_BINDING,
      #      :vlan_mask=>0xffffffff
      #    )
      def add_vlan(opt)
        add_link(vlan_options(opt))
      end
      
      def change_vlan(opt)
        change_link(vlan_options(opt))
      end
      
      def replace_vlan(opt)
        replace_link(vlan_options(opt))
      end
      
      # Delete vlan given :link and :vlan_id. If you want to delete
      # by :index then call delete_link instead.
      def delete_vlan(opt)
        raise "Missing vlan_id" unless opt[:vlan_id]
        raise "Missing link" unless opt[:link]
        link = links(:kind=>"vlan", :link=>opt[:link]).find { |l|
            l.linkinfo.data &&
            l.linkinfo.data.id == opt[:vlan_id]
        }
        raise Errno::ENODEV unless link
        delete_link(link.index)
      end

      def vlan_options(orig) #:nodoc:
        opt = orig.dup
        opt[:link] = index(opt.fetch(:link))
        li = opt[:linkinfo] ||= LinkInfo.new
        li.kind = "vlan"
        li.data ||= VlanInfo.new
        li.data.id = opt.delete(:vlan_id) if opt.has_key?(:vlan_id)
        if opt.has_key?(:vlan_flags)
          li.data.flags ||= VlanFlags.new(:flags => opt.delete(:vlan_flags))
          li.data.flags.mask = opt.delete(:vlan_mask) if opt.has_key?(:vlan_mask)
        end
        li.data.egress_qos = opt.delete(:egress_qos) if opt.has_key?(:egress_qos)
        li.data.ingress_qos = opt.delete(:ingress_qos) if opt.has_key?(:ingress_qos)
        opt
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
          links do |link|
            h[link.ifname] = {}
          end
          read_addrs.each do |addr|
            ifname = name(addr.index)
            h[ifname] ||= Hash.new(EMPTY_ARRAY)
            (h[ifname][addr.family] ||= []) << addr
          end
          h
        )
      end

      # Add an IP address to an interface
      #
      #    require 'netlink/route'
      #    rt = Netlink::Route::Socket.new
      #    rt.add_addr(:index=>"eth0", :local=>"1.2.3.4", :prefixlen=>24)
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
        msg.index = index(msg.index) unless msg.index.is_a?(Integer)
        msg.address ||= msg.local
        # Note: IPAddr doesn't support addresses off the subnet base,
        # so there's no point trying to set msg.prefixlen from the IPAddr mask
        @nlsocket.cmd code, msg, flags|NLM_F_REQUEST
        clear_addr_cache
      end
    end
  end
end
