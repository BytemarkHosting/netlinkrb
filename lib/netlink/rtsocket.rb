require 'netlink/nlsocket'
require 'netlink/message'

module Netlink
  # This is the high-level API using a NETLINK_ROUTE protocol socket
  class RTSocket < NLSocket
    def initialize(opt={})
      super(opt.merge(:protocol => Netlink::NETLINK_ROUTE))
    end

    # List links (interfaces). Returns an array of Netlink::Link objects.
    #   res = nl.link_list
    #   p res
    #   [#<Netlink::Link {:family=>0, :pad=>0, :type=>772, :index=>1,
    #    :flags=>65609, :change=>0, :ifname=>"lo", :txqlen=>0, :operstate=>0,
    #    :linkmode=>0, :mtu=>16436, :qdisc=>"noqueue", :map=>"...",
    #    :address=>"\x00\x00\x00\x00\x00\x00", :broadcast=>"\x00\x00\x00\x00\x00\x00",
    #    :stats=>#<struct Netlink::LinkStats rx_packets=22, ...>,
    #    :stats64=>#<struct Netlink::LinkStats rx_packets=22, ...>}>, ...]
    def links(opt=nil)
      send_request RTM_GETLINK, Link.new(opt),
                   NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST
      receive_until_done(RTM_NEWLINK)
    end

    # Return a Hash of Netlink::Link objects keyed by interface index, which
    # is what the 'routes' and 'addrs' objects point to.
    def links_by_index(opt=nil)
      res = {}
      links(opt).each { |obj| res[obj.index] = obj }
      res
    end
      
    # List routes. Returns an array of Netlink::Route objects
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
    def routes(opt=nil)
      send_request RTM_GETROUTE, Route.new(opt),
                   NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST
      receive_until_done(RTM_NEWROUTE)
    end
    
    # Return routes as a hash of {index=>[route,route], index=>[route,route]}
    def routes_by_oif(opt=nil)
      res = routes(opt).group_by { |obj| obj.oif }
      res.default = [].freeze
      res
    end

    # List addresses. Return an array of Netlink::Addr objects.
    # You will need to use the 'index' to cross reference to the interface.
    #   res = nl.addrs(:family => Socket::AF_INET)
    #   p res
    #   [#<Netlink::Addr {:family=>2, :prefixlen=>8, :flags=>128, :scope=>254,
    #    :index=>1, :address=>#<IPAddr: IPv4:127.0.0.1/255.255.255.255>,
    #    :local=>#<IPAddr: IPv4:127.0.0.1/255.255.255.255>, :label=>"lo"}>, ...]
    def addrs(opt=nil)
      send_request RTM_GETADDR, Addr.new(opt),
                   NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST
      receive_until_done(RTM_NEWADDR)
    end

    # Return addresses as a hash of {index=>[addr,addr], index=>[addr,addr]}
    def addrs_by_index(opt=nil)
      res = addrs(opt).group_by { |obj| obj.index }
      res.default = [].freeze
      res
    end
  end
end

if __FILE__ == $0
  require 'pp'
  nl = Netlink::RTSocket.new
  #puts "*** routes ***"
  #pp nl.routes(:family => Socket::AF_INET)
  #puts "*** links ***"
  #pp nl.links(:family => Socket::AF_INET)
  #puts "*** addrs ***"
  #pp nl.addrs(:family => Socket::AF_INET)
  links = nl.links
  addrs = nl.addrs_by_index(:family=>Socket::AF_UNSPEC)
  routes = nl.routes_by_oif(:family=>Socket::AF_UNSPEC)
  links.each do |link|
    #p link
    puts "#{link.ifname}"
    addrs[link.index].each do |addr|
      #p addr
      puts "  family=#{addr.family} #{addr.address}/#{addr.prefixlen} label=#{addr.label}"
    end
    routes[link.index].each do |route|
      #p route
      puts "  >> family=#{route.family} #{route.dst}/#{route.dst_len} gw=#{route.gateway}"
    end
  end
end
