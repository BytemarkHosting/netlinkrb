# This file implements the messages and methods for the NETLINK_ROUTE protocol.
# Apart from a few utility functions for converting ifname to index and vice
# versa, the logic is delegated to separate classes for each entity
# (links, addresses etc)

require 'linux/netlink/nlsocket'
require 'linux/netlink/message'

module Linux
module Netlink
  module Route
    autoload :LinkHandler, 'linux/netlink/route/link_handler'
    autoload :VlanHandler, 'linux/netlink/route/vlan_handler'
    autoload :AddrHandler, 'linux/netlink/route/addr_handler'
    autoload :RouteHandler, 'linux/netlink/route/route_handler'
    
    # This class formats and receives messages using NETLINK_ROUTE protocol
    class Socket < NLSocket
      def initialize(opt={})
        super(opt.merge(:protocol => Linux::NETLINK_ROUTE))
      end

      # Return a LinkHandler object for manipulating links
      def link
        @link ||= LinkHandler.new(self)
      end
      
      # Return a VlanHandler object for manipulating vlans
      def vlan
        @vlan ||= VlanHandler.new(self)
      end
      
      # Return a AddrHandler object for manipulating addresses
      def addr
        @addr ||= AddrHandler.new(self)
      end
      
      # Return a RT object for manipulating routes
      def route
        @route ||= RouteHandler.new(self)
      end

      # Convert an interface index into name string, or nil if the
      # index is nil or 0. Raises exception for unknown values.
      #
      #    ip = Linux::Netlink::Route::Socket.new
      #    ip.route(:family=>Socket::AF_INET) do |route|
      #      puts "iif=#{ip.ifname(route.iif)}"
      #      puts "oif=#{ip.ifname(route.oif)}"
      #    end
      def ifname(index)
        return nil if index.nil? || index == 0
        link[index].ifname
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
          link[name].index
        end
      end
    end
  end
end
end # module Linux
