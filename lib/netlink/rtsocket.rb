require 'netlink/nlsocket'
require 'netlink/message'

module Netlink
  # This is the medium and high-level API using a NETLINK_ROUTE protocol socket
  class RTSocket < NLSocket
    def initialize(opt={})
      super(opt.merge(:protocol => Netlink::NETLINK_ROUTE))
      clear_cache
    end

    # Download a list of links (interfaces). Either returns an array of
    # Netlink::Link objects, or yields them to the supplied block.
    #
    #   res = nl.link_list
    #   p res
    #   [#<Netlink::Link {:family=>0, :pad=>0, :type=>772, :index=>1,
    #    :flags=>65609, :change=>0, :ifname=>"lo", :txqlen=>0, :operstate=>0,
    #    :linkmode=>0, :mtu=>16436, :qdisc=>"noqueue", :map=>"...",
    #    :address=>"\x00\x00\x00\x00\x00\x00", :broadcast=>"\x00\x00\x00\x00\x00\x00",
    #    :stats=>#<struct Netlink::LinkStats rx_packets=22, ...>,
    #    :stats64=>#<struct Netlink::LinkStats rx_packets=22, ...>}>, ...]
    def read_links(opt=nil, &blk)
      send_request RTM_GETLINK, Link.new(opt),
                   NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST
      receive_until_done(RTM_NEWLINK, &blk)
    end

    # Download a list of routes. Either returns an array of
    # Netlink::Route objects, or yields them to the supplied block.
    #
    # A hash of kernel options may be supplied, but you might also have
    # to perform your own filtering. e.g.
    #   rt.read_routes(:family=>Socket::AF_INET)           # works
    #   rt.read_routes(:protocol=>Netlink::RTPROT_STATIC)  # ignored
    #
    #   res = nl.routes(:family => Socket::AF_INET)
    #   p res
    #   [#<Netlink::Route {:family=>2, :dst_len=>32, :src_len=>0, :tos=>0,
    #    :table=>255, :protocol=>2, :scope=>253, :type=>3, :flags=>0, :table2=>255,
    #    :dst=>#<IPAddr: IPv4:127.255.255.255/255.255.255.255>,
    #    :prefsrc=>#<IPAddr: IPv4:127.0.0.1/255.255.255.255>, :oif=>1}>, ...]
    #
    # Note that not all attributes will always be present. In particular,
    # a defaultroute (dst_len=0) misses out the dst address completely:
    #
    #   [#<Netlink::Route {:family=>2, :dst_len=>0, :src_len=>0, :tos=>0,
    #    :table=>254, :protocol=>4, :scope=>0, :type=>1, :flags=>0, :table2=>254,
    #    :gateway=>#<IPAddr: IPv4:10.69.255.253/255.255.255.255>, :oif=>2}>, ...]
    def read_routes(opt=nil, &blk)
      send_request RTM_GETROUTE, Route.new(opt),
                   NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST
      receive_until_done(RTM_NEWROUTE, &blk)
    end
    
    # Download a list of link addresses. Either returns an array of
    # Netlink::Addr objects, or yields them to the supplied block.
    # You will need to use the 'index' to cross reference to the interface.
    #
    # A hash of kernel options may be supplied, but likely only :family
    # is honoured.
    #
    #   res = nl.addrs(:family => Socket::AF_INET)
    #   p res
    #   [#<Netlink::Addr {:family=>2, :prefixlen=>8, :flags=>128, :scope=>254,
    #    :index=>1, :address=>#<IPAddr: IPv4:127.0.0.1/255.255.255.255>,
    #    :local=>#<IPAddr: IPv4:127.0.0.1/255.255.255.255>, :label=>"lo"}>, ...]
    def read_addrs(opt=nil, &blk)
      send_request RTM_GETADDR, Addr.new(opt),
                   NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST
      receive_until_done(RTM_NEWADDR, &blk)
    end

    # Download a list of addresses, grouped as {index=>[addr,addr], index=>[addr,addr]}
    def read_addrs_by_ifindex(opt=nil)
      res = read_addrs(opt).group_by { |obj| obj.index }
      res.default = [].freeze
      res
    end

    # Clear the memoization cache
    def clear_cache
      @links = nil
      @addrs = nil
      @routes = nil
    end
    
    # Return the memoized interface table, keyed by interface name. e.g.
    #    puts rt.links["eth0"].type
    def links
      @links ||= (
        res = {}
        read_links.each { |obj| res[obj.ifname] = obj }
        res
      )
    end

    EMPTY_ARRAY = [].freeze #:nodoc:
    
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
        index_to_link = {}
        links.each do |name, link|
          h[link.ifname] = {}
          index_to_link[link.index] = link
        end
        read_addrs.each do |addr|
          ifname = index_to_link[addr.index].ifname
          h[ifname] ||= Hash.new(EMPTY_ARRAY)
          (h[ifname][addr.family] ||= []) << addr
        end
        h
      )
    end

    # Return the memoized route table, keyed by output interface name and
    # address family, containing an array of routes for each interface/
    # family combination. i.e.
    #
    #   # {ifname=>{family=>[route,route,...], ...}, ...}
    #   puts rt.routes["eth0"][Socket::AF_INET].first.dst
    #
    # If there are no routes for a particular family then it will
    # return a (frozen) empty array, to make iteration eaiser.
    def routes
      @routes ||= (
        h = {}
        index_to_link = {}
        links.each do |name, link|
          h[link.ifname] = {}
          index_to_link[link.index] = link
        end
        read_routes.each do |route|
          ifname = index_to_link[route.oif].ifname
          h[ifname] ||= Hash.new(EMPTY_ARRAY)
          (h[ifname][route.family] ||= []) << route
        end
        h
      )
    end
  end
end

if __FILE__ == $0
  require 'pp'
  nl = Netlink::RTSocket.new
  #puts "*** routes ***"
  #pp nl.read_routes(:family => Socket::AF_INET)
  #puts "*** links ***"
  #pp nl.read_links
  #puts "*** addrs ***"
  #pp nl.read_addrs(:family => Socket::AF_INET)
  pp nl.links["eth0"]
  pp nl.addrs["eth0"]
  pp nl.routes["eth0"][Socket::AF_INET].min_by { |route| route.dst_len }
end
