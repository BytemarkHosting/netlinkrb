# This file implements the messages and methods for the NETLINK_ROUTE protocol.
# Apart from a few utility functions for converting ifname to index and vice
# versa, the logic is delegated to separate classes for each entity
# (links, addresses etc)

require 'netlink/nlsocket'
require 'netlink/message'

module Netlink
  module Route
    autoload :LinkHandler, 'netlink/route/link_handler'
    autoload :VlanHandler, 'netlink/route/vlan_handler'
    autoload :AddrHandler, 'netlink/route/addr_handler'
    autoload :RouteHandler, 'netlink/route/route_handler'
    
    # This class formats and receives messages using NETLINK_ROUTE protocol
    class Socket < NLSocket
      def initialize(opt={})
        super(opt.merge(:protocol => Netlink::NETLINK_ROUTE))
      end

      # Return a Netlink::Route::LinkHandler object for manipulating links
      def links
        @links ||= Netlink::Route::LinkHandler.new(self)
      end
      
      # Return a Netlink::Route::VlanHandler object for manipulating vlans
      def vlans
        @vlans ||= Netlink::Route::VlanHandler.new(self)
      end
      
      # Return a Netlink::Route::AddrHandler object for manipulating addresses
      def addrs
        @addrs ||= Netlink::Route::AddrHandler.new(self)
      end
      
      # Return a Netlink::Route::RT object for manipulating routes
      def routes
        @routes ||= Netlink::Route::RouteHandler.new(self)
      end

      # Convert an interface index into name string, or nil if the
      # index is nil or empty string. Raises exception for unknown values.
      #
      #    nl = Netlink::Route::Socket.new
      #    nl.routes(:family=>Socket::AF_INET) do |route|
      #      puts "iif=#{nl.ifname(route.iif)}"
      #      puts "oif=#{nl.ifname(route.oif)}"
      #    end
      def ifname(index)
        return nil if index.nil? || index == 0
        links[index].ifname
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
          links[name].index
        end
      end
    end
  end
end
