require 'netlink/nlsocket'
require 'netlink/message'

module Netlink
  # This is the high-level API using a NETLINK_ROUTE protocol socket
  class RTSocket < NLSocket
    def initialize(opt={})
      super(opt.merge(:protocol => Netlink::NETLINK_ROUTE))
    end

    # List links. Returns an array of Netlink::Link objects
    def link_list(opt)
      send_request RTM_GETLINK, Link.new(opt),
                   NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST
      receive_until_done
    end

    # List routes. Returns an array of Netlink::Route objects
    #   res = nl.routes(:family => Socket::AF_INET)
    #   #=> [..., ...]
    def route_list(opt)
      send_request RTM_GETROUTE, Route.new(opt),
                   NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST
      receive_until_done
    end

    def addr_list(opt)
      send_request RTM_GETADDR, Addr.new(opt),
                   NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST
      receive_until_done
    end

    # Add a route
    #    nl.add_route(:family => Socket::AF_INET, ...)
    def route_add(r)
      send_request RTM_NEWROUTE, Route.new(r)
      # Do we get any success/fail?
    end

    # Delete a route
    def route_delete(r)
      send_request RTM_DELROUTE, Route.new(r)
    end
  end
end

if __FILE__ == $0
  require 'pp'
  nl = Netlink::RTSocket.new
  pp nl.route_list(:family => Socket::AF_INET)
  pp nl.link_list(:family => Socket::AF_INET)
  pp nl.addr_list(:family => Socket::AF_INET)
end
