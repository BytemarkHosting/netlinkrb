# This file implements the messages and methods for the NETLINK_ROUTE protocol

require 'netlink/nlsocket'
require 'netlink/message'

module Netlink
  module Route
    autoload :IFHandler, 'netlink/route/if_handler'
    autoload :RTHandler, 'netlink/route/rt_handler'
    
    # This class formats and receives messages using NETLINK_ROUTE protocol
    class Socket < NLSocket
      def initialize(opt={})
        super(opt.merge(:protocol => Netlink::NETLINK_ROUTE))
      end

      # Return a Netlink::Route::IF object for manipulating interfaces
      # and interface addresses
      def if(reload=false)
        @if = nil if reload
        @if ||= Netlink::Route::IFHandler.new(self)
      end
      
      # Return a Netlink::Route::RT object for manipulating routes
      def rt(reload=false)
        @rt = nil if reload
        @rt ||= Netlink::Route::RTHandler.new(self)
      end
    end
  end
end
