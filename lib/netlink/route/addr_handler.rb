require 'netlink/route'

module Netlink
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
    class AddrHandler
      def initialize(rtsocket = Netlink::Route::Socket.new)
        @rtsocket = rtsocket
        clear_cache
      end

      def clear_cache
        @addrs = nil
      end

      def index(v)
        @rtsocket.index(v)
      end

      def ifname(v)
        @rtsocket.ifname(v)
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
        @rtsocket.send_request RTM_GETADDR, IFAddr.new(opt),
                     NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST
        @rtsocket.receive_until_done(RTM_NEWADDR, &blk)
      end

      # Iterate over all addresses, or addressees matching the given
      # criteria. Returns an Enumerator if no block given.
      #
      # The full address list is read once and memoized, so
      # it is efficient to call this method multiple times.
      #
      #    nl.addrs.list { |x| p x }
      #    addrs_eth0 = nl.addrs.list(:index=>"eth0").to_a
      #    addrs_eth0_v4 = nl.addrs.list(:index=>"eth0", :family=>Socket::AF_INET).to_a
      #
      # TODO: error on unknown filter conditions
      def list(filter=nil, &blk)
        @addrs ||= read_addrs
        return @addrs.each(&blk) unless filter
        return to_enum(:list, filter) unless block_given?
        filter[:index] = index(filter[:index]) if filter.has_key?(:index)
        @addrs.each do |o|
          yield o if (!filter[:family] || o.family == filter[:family]) &&
          (!filter[:scope] || o.kind?(filter[:scope])) &&
          (!filter[:flags] || (o.flags & filter[:flags]) == filter[:flags]) &&
          (!filter[:noflags] || (o.flags & filter[:noflags]) == 0) &&
          (!filter[:index] || o.index == filter[:index])
        end
      end
      alias :each :list
      
      # Return addresses grouped by interface name. e.g.
      #    addrs_by_interface(:family => Socket::AF_INET).to_a
      #    #=> {"eth0"=>[addr, addr,...], "lo"=>[addr, addr,...]
      #
      # The hash has an empty array as its default, so it's safe to do
      #    addrs_by_interface(...)["eth0"].each { |a| ... }
      # even if eth0 has no addresses matching the given filter.
      def group_by_interface(*filter)
        res = list(*filter).group_by { |a| ifname(a.index) }
        res.default = EMPTY_ARRAY
        res
      end
        
      # Add an IP address to an interface
      #
      #    require 'netlink/route'
      #    rt = Netlink::Route::Socket.new
      #    rt.add(:index=>"eth0", :local=>"1.2.3.4", :prefixlen=>24)
      def add(opt)
        ipaddr_modify(RTM_NEWADDR, NLM_F_CREATE|NLM_F_EXCL, opt)
      end

      def change(opt)
        ipaddr_modify(RTM_NEWADDR, NLM_F_REPLACE, opt)
      end
      
      def replace(opt)
        ipaddr_modify(RTM_NEWADDR, NLM_F_CREATE|NLM_F_REPLACE, opt)
      end
      
      # Delete an IP address from an interface. Pass in either a hash of
      # parameters, or an existing IFAddr object.
      def delete(opt)
        ipaddr_modify(RTM_DELADDR, 0, opt)
      end
      
      def ipaddr_modify(code, flags, msg) #:nodoc:
        msg = IFAddr.new(msg)
        msg.index = index(msg.index) unless msg.index.is_a?(Integer)
        msg.address ||= msg.local
        # Note: IPAddr doesn't support addresses off the subnet base,
        # so there's no point trying to set msg.prefixlen from the IPAddr mask
        @rtsocket.cmd code, msg, flags|NLM_F_REQUEST
        clear_cache
      end
    end
  end
end
