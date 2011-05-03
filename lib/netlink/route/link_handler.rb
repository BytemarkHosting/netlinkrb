require 'netlink/route'

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

  module Route
    # This class provides an API for manipulating interfaces and addresses.
    # Since we frequently need to map ifname to ifindex, or vice versa,
    # we keep a memoized list of interfaces. If the interface list changes,
    # you should create a new instance of this object.
    class LinkHandler
      def initialize(rtsocket = Netlink::Route::Socket.new)
        @rtsocket = rtsocket
        clear_cache
      end

      def clear_cache
        @links = nil
        @linkmap = nil
      end

      def index(v)
        @rtsocket.index(v)
      end
            
      # Download a list of links (interfaces). Either returns an array of
      # Netlink::IFInfo objects, or yields them to the supplied block.
      #
      #   res = rt.links.read_links
      #   p res
      #   [#<Netlink::IFInfo {:family=>0, :type=>772, :index=>1,
      #    :flags=>65609, :change=>0, :ifname=>"lo", :txqlen=>0, :operstate=>0,
      #    :linkmode=>0, :mtu=>16436, :qdisc=>"noqueue", :map=>"...",
      #    :address=>"\x00\x00\x00\x00\x00\x00", :broadcast=>"\x00\x00\x00\x00\x00\x00",
      #    :stats32=>#<struct Netlink::LinkStats rx_packets=22, ...>,
      #    :stats64=>#<struct Netlink::LinkStats rx_packets=22, ...>}>, ...]
      def read_links(opt=nil, &blk)
        @rtsocket.send_request RTM_GETLINK, IFInfo.new(opt),
                     NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST
        @rtsocket.receive_until_done(RTM_NEWLINK, &blk)
      end

      # Iterate over all interfaces, or interfaces matching the given
      # criteria. Returns an Enumerator if no block given.
      #
      # The full interface list is read once and memoized, so
      # it is efficient to call this method multiple times.
      #
      #    rt.links.list { |x| p x }
      #    ethers = rt.links.list(:type => Netlink::ARPHRD_ETHER).to_a
      #    vlans = rt.links.list(:kind => "vlan").to_a
      #    rt.links.list(:flags => Netlink::IFF_RUNNING)
      #    rt.links.list(:noflags => Netlink::IFF_POINTOPOINT)
      #    rt.links.list(:link => "lo")   # vlan etc attached to this interface
      def list(filter=nil, &blk)
        @links ||= read_links
        return @links.each(&blk) unless filter
        return to_enum(:list, filter) unless block_given?
        filter[:link] = index(filter[:link]) if filter.has_key?(:link)
        @links.each do |o|
          yield o if (!filter[:type] || o.type == filter[:type]) &&
          (!filter[:kind] || o.kind?(filter[:kind])) &&
          (!filter[:flags] || (o.flags & filter[:flags]) == filter[:flags]) &&
          (!filter[:noflags] || (o.flags & filter[:noflags]) == 0) &&
          (!filter[:link] || o.link == filter[:link])
        end
      end
      alias :each :list
            
      # Return a memoized Hash of interfaces, keyed by both index and name
      def linkmap
        @linkmap ||= (
          h = {}
          list { |link| h[link.index] = h[link.ifname] = link }
          h
        )
      end
      
      # Return details of one interface, given its name or index.
      # Raises exception if unknown value.
      def [](key)
        linkmap.fetch(key)
      end
      
      # Add an interface (raw). e.g.
      #
      #    require 'netlink/route'
      #    rt = Netlink::Route::Socket.new
      #    rt.links.add_link(
      #        :link=>"lo",
      #        :linkinfo=>Netlink::LinkInfo.new(
      #            :kind=>"vlan",
      #            :data=>Netlink::VlanInfo.new(
      #                :id=>1234,
      #                :flags => Netlink::VlanFlags.new(
      #                    :flags=>Netlink::VLAN_FLAG_LOOSE_BINDING,
      #                    :mask=>0xffffffff
      #    ))))
                      
      def add(opt)
        iplink_modify(RTM_NEWLINK, NLM_F_CREATE|NLM_F_EXCL, opt)
      end

      def change(opt)
        iplink_modify(RTM_NEWLINK, NLM_F_REPLACE, opt)
      end
      
      def replace(opt)
        iplink_modify(RTM_NEWLINK, NLM_F_CREATE|NLM_F_REPLACE, opt)
      end

      # Delete an existing link. Pass in ifname or index, or options
      # hash {:index=>n}
      def delete(opt)
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

        @rtsocket.cmd code, msg, flags|NLM_F_REQUEST
        clear_cache
      end
    end
  end
end
