require 'linux/netlink/route'
require 'linux/netlink/route/route_handler'

module Linux
module Netlink

  module Route
    # This class manipulates the kernel routing table by adding and removing
    # rules
    class RuleHandler < Handler
      def clear_cache
        @rule = nil
      end

      def read_rule(opt=nil, &blk)
        @rtsocket.send_request RTM_GETRULE, RT.new(opt),
                     NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST
        @rtsocket.receive_until_done(RTM_NEWRULE, &blk)
      end


      Filter = RouteHandler::Filter

      # Return the memoized rule list, filtered according to
      # the optional criteria. Examples:
      #    :family => Socket::AF_INET
      #    :table => Linux::RT_TABLE_DEFAULT
      #    :protocol => Linux::RTPROT_STATIC
      #    :type => Linux::RTN_UNICAST
      #    :scope => Linux::RT_SCOPE_HOST
      #    :flags => Linux::RTM_F_NOTIFY
      #    :noflags => Linux::RTM_F_CLONED
      #    :oif => "eth0"
      #    :iif => "eth1"
      def list(filter=nil, &blk)
        @rule ||= read_rule
        filter[:oif] = index(filter[:oif]) if filter && filter.has_key?(:oif)
        filter[:iif] = index(filter[:iif]) if filter && filter.has_key?(:iif)
        filter_list(@rule, filter, &blk)
      end
      alias :each :list

      def add(opt)
        iproute_modify(RTM_NEWRULE, NLM_F_CREATE|NLM_F_EXCL, opt)
      end

      def delete(opt)
        iproute_modify(RTM_DELRULE, 0, opt)
      end

      # Get route matching given criteria
      def get(msg)
        msg = RT.new(msg)
        raise "Missing :dst" unless msg.dst
        msg.iif = index(msg.iif) if msg.iif.is_a?(String)
        msg.oif = index(msg.oif) if msg.oif.is_a?(String)
        @rtsocket.cmd RTM_GETRULE, msg, NLM_F_REQUEST, RTM_NEWRULE
      end

      def iproute_modify(code, flags, msg) #:nodoc:
        msg = RT.new(msg)

        if code != RTM_DELRULE
          msg.protocol ||= RTPROT_BOOT
          msg.type ||= RTN_UNICAST
        end
        # There is scary code in ip/iproute.c for setting defaults
        unless msg.table
          msg.table = case msg.type
          when RTN_LOCAL, RTN_BROADCAST, RTN_NAT, RTN_ANYCAST
            RT_TABLE_LOCAL
          else
            RT_TABLE_MAIN
          end
        end
        unless msg.scope
          msg.scope = (code != RTM_DELRULE) ? RT_SCOPE_UNIVERSE : RT_SCOPE_NOWHERE
          case msg.type
          when RTN_LOCAL, RTN_NAT
            msg.scope = RT_SCOPE_HOST
          when RTN_BROADCAST, RTN_MULTICAST, RTN_ANYCAST
            msg.scope RT_SCOPE_LINK
          when RTN_UNICAST, RTN_UNSPEC
            if code == RTM_DELRULE
              msg.scope = RT_SCOPE_NOWHERE
            elsif !msg.gateway && !msg.multipath
              msg.scope = RT_SCOPE_LINK
            end
          end
        end

        msg.iif = index(msg.iif) if msg.iif.is_a?(String)
        msg.oif = index(msg.oif) if msg.oif.is_a?(String)

        @rtsocket.cmd code, msg, flags|NLM_F_REQUEST
        clear_cache
      end
    end
  end
end
end # module Linux

