require 'linux/netlink/route'
require 'linux/netlink/route/handler'

module Linux
module Netlink
  # struct rta_cacheinfo
  RTACacheInfo = Struct.new :clntref, :lastuse, :expires, :error, :used, :id, :ts, :tsage

  # struct rtmsg
  class RT < RtattrMessage
    code RTM_NEWROUTE, RTM_DELROUTE, RTM_GETROUTE

    field :family, :uchar			# Socket::AF_*
    field :dst_len, :uchar
    field :src_len, :uchar
    field :tos, :uchar
    field :table, :uchar			# table id or RT_TABLE_*
    field :protocol, :uchar			# RTPROT_*
    field :scope, :uchar			# RT_SCOPE_*
    field :type, :uchar				# RTN_*
    field :flags, :uint				# RTM_F_*
    rtattr :dst, RTA_DST, :l3addr
    rtattr :src, RTA_SRC, :l3addr
    rtattr :iif, RTA_IIF, :uint32
    rtattr :oif, RTA_OIF, :uint32
    rtattr :gateway, RTA_GATEWAY, :l3addr
    rtattr :priority, RTA_PRIORITY, :uint32
    rtattr :prefsrc, RTA_PREFSRC, :l3addr
    rtattr :metrics, RTA_METRICS,
      :unpack => lambda { |str,obj| RTAMetrics.parse(str) }
    rtattr :multipath, RTA_MULTIPATH
    rtattr :flow, RTA_FLOW
    rtattr :cacheinfo, RTA_CACHEINFO,
        :pack   => lambda { |val,obj| val.to_a.pack("L*") },
        :unpack => lambda { |str,obj| RTACacheInfo.new(*(str.unpack("L*"))) }
    rtattr :table2, RTA_TABLE, :uint32   # NOTE: table in two places!
  end

  class RTAMetrics < RtattrMessage
    rtattr :lock,	RTAX_LOCK,	:uint32
    rtattr :mtu,	RTAX_MTU,	:uint32
    rtattr :window,	RTAX_WINDOW,	:uint32
    rtattr :rtt,	RTAX_RTT,	:uint32
    rtattr :rttvar,	RTAX_RTTVAR,	:uint32
    rtattr :ssthresh,	RTAX_SSTHRESH,	:uint32
    rtattr :cwnd,	RTAX_CWND,	:uint32
    rtattr :advmss,	RTAX_ADVMSS,	:uint32
    rtattr :reordering,	RTAX_REORDERING, :uint32
    rtattr :hoplimit,	RTAX_HOPLIMIT,	:uint32
    rtattr :initcwnd,	RTAX_INITCWND,	:uint32
    rtattr :features,	RTAX_FEATURES,	:uint32
    rtattr :rto_min,	RTAX_RTO_MIN,	:uint32
    rtattr :initrwnd,	RTAX_INITRWND,	:uint32
  end

  module Route
    # This class manipulates the kernel routing table
    class RouteHandler < Handler
      def clear_cache
        @route = nil
      end
      
      # Send message to download the kernel routing table. Either returns an
      # array of Netlink::RT objects, or yields them to the supplied block.
      #
      # A hash of kernel options may be supplied, but you might also have
      # to perform your own filtering. e.g.
      #   read_route(:family=>Socket::AF_INET)         # works
      #   read_route(:protocol=>Linux::RTPROT_STATIC)  # ignored
      #
      #   res = ip.route.read_route(:family => Socket::AF_INET)
      #   p res
      #   [#<Linux::Netlink::RT {:family=>2, :dst_len=>32, :src_len=>0, :tos=>0,
      #    :table=>255, :protocol=>2, :scope=>253, :type=>3, :flags=>0, :table2=>255,
      #    :dst=>#<IPAddr: IPv4:127.255.255.255/255.255.255.255>,
      #    :prefsrc=>#<IPAddr: IPv4:127.0.0.1/255.255.255.255>, :oif=>1}>, ...]
      #
      # Note that not all attributes will always be present. In particular,
      # a defaultroute (dst_len=0) misses out the dst address completely:
      #
      #   [#<Linux::Netlink::RT {:family=>2, :dst_len=>0, :src_len=>0, :tos=>0,
      #    :table=>254, :protocol=>4, :scope=>0, :type=>1, :flags=>0, :table2=>254,
      #    :gateway=>#<IPAddr: IPv4:10.69.255.253/255.255.255.255>, :oif=>2}>, ...]
      def read_route(opt=nil, &blk)
        @rtsocket.send_request RTM_GETROUTE, RT.new(opt),
                     NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST
        @rtsocket.receive_until_done(RTM_NEWROUTE, &blk)
      end

      class Filter < BaseFilter #:nodoc:
        filter(:family) { |o,v| o.family == v }
        filter(:table) { |o,v| o.table == v }
        filter(:protocol) { |o,v| o.protocol == v }
        filter(:type) { |o,v| o.type == v }
        filter(:scope) { |o,v| o.scope == v }
        filter(:flags) { |o,v| (o.flags & v) == v }
        filter(:noflags) { |o,v| (o.flags & v) == 0 }
        filter(:oif) { |o,v| o.oif == v }
        filter(:iif) { |o,v| o.iif == v }
      end
      
      # Return the memoized route table, filtered according to
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
        @route ||= read_route
        filter[:oif] = index(filter[:oif]) if filter && filter.has_key?(:oif)
        filter[:iif] = index(filter[:iif]) if filter && filter.has_key?(:iif)
        filter_list(@route, filter, &blk)
      end
      alias :each :list
      
      def add(opt)
        iproute_modify(RTM_NEWROUTE, NLM_F_CREATE|NLM_F_EXCL, opt)
      end

      def change(opt)
        iproute_modify(RTM_NEWROUTE, NLM_F_REPLACE, opt)
      end
      
      def replace(opt)
        iproute_modify(RTM_NEWROUTE, NLM_F_CREATE|NLM_F_REPLACE, opt)
      end

      def prepend(opt)
        iproute_modify(RTM_NEWROUTE, NLM_F_CREATE, opt)
      end

      def append(opt)
        iproute_modify(RTM_NEWROUTE, NLM_F_CREATE|NLM_F_APPEND, opt)
      end

      def test(opt)
        iproute_modify(RTM_NEWROUTE, NLM_F_EXCL, opt)
      end

      def delete(opt)
        iproute_modify(RTM_DELROUTE, 0, opt)
      end

      # Get route matching given criteria
      def get(msg)
        msg = RT.new(msg)
        raise "Missing :dst" unless msg.dst
        msg.iif = index(msg.iif) if msg.iif.is_a?(String)
        msg.oif = index(msg.oif) if msg.oif.is_a?(String)
        @rtsocket.cmd RTM_GETROUTE, msg, NLM_F_REQUEST, RTM_NEWROUTE
      end
      
      def iproute_modify(code, flags, msg) #:nodoc:
        msg = RT.new(msg)
        
        if code != RTM_DELROUTE
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
          msg.scope = (code != RTM_DELROUTE) ? RT_SCOPE_UNIVERSE : RT_SCOPE_NOWHERE
          case msg.type
          when RTN_LOCAL, RTN_NAT
            msg.scope = RT_SCOPE_HOST
          when RTN_BROADCAST, RTN_MULTICAST, RTN_ANYCAST
            msg.scope RT_SCOPE_LINK
          when RTN_UNICAST, RTN_UNSPEC
            if code == RTM_DELROUTE
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
