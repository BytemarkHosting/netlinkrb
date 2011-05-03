require 'netlink/route'

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
    # Route metrics are themselves packed using the rtattr format.
    # In the kernel, the dst.metrics structure is an array of u32.
    METRIC_PACK = "SSL".freeze #:nodoc:
    METRIC_SIZE = [0,0,0].pack(METRIC_PACK).bytesize #:nodoc:
    rtattr :metrics, RTA_METRICS,		# {RTAX_* => Integer}
        :pack   => lambda { |metrics,obj|
          metrics.map { |code,val| [METRIC_SIZE,code,val].pack(METRIC_PACK) }.join
        },
        :unpack => lambda { |str,obj|
          res = {}
          RtattrMessage.unpack_rtattr(str) { |code,val| res[code] = val.unpack("L").first }
          res
        }
    rtattr :multipath, RTA_MULTIPATH
    rtattr :flow, RTA_FLOW
    rtattr :cacheinfo, RTA_CACHEINFO,
        :pack   => lambda { |val,obj| val.to_a.pack("L*") },
        :unpack => lambda { |str,obj| RTACacheInfo.new(*(str.unpack("L*"))) }
    rtattr :table2, RTA_TABLE, :uint32   # NOTE: table in two places!
  end

  module Route
    # This class manipulates the kernel routing table
    class RouteHandler
      def initialize(rtsocket = Netlink::Route::Socket.new)
        @rtsocket = rtsocket
        clear_cache
      end
      
      def clear_cache
        @routes = nil
      end
      
      def index(v)
        @rtsocket.index(v)
      end
      
      # Send message to download the kernel routing table. Either returns an
      # array of Netlink::RT objects, or yields them to the supplied block.
      #
      # A hash of kernel options may be supplied, but you might also have
      # to perform your own filtering. e.g.
      #   read_routes(:family=>Socket::AF_INET)           # works
      #   read_routes(:protocol=>Netlink::RTPROT_STATIC)  # ignored
      #
      #   res = rt.routes.read_routes(:family => Socket::AF_INET)
      #   p res
      #   [#<Netlink::RT {:family=>2, :dst_len=>32, :src_len=>0, :tos=>0,
      #    :table=>255, :protocol=>2, :scope=>253, :type=>3, :flags=>0, :table2=>255,
      #    :dst=>#<IPAddr: IPv4:127.255.255.255/255.255.255.255>,
      #    :prefsrc=>#<IPAddr: IPv4:127.0.0.1/255.255.255.255>, :oif=>1}>, ...]
      #
      # Note that not all attributes will always be present. In particular,
      # a defaultroute (dst_len=0) misses out the dst address completely:
      #
      #   [#<Netlink::RT {:family=>2, :dst_len=>0, :src_len=>0, :tos=>0,
      #    :table=>254, :protocol=>4, :scope=>0, :type=>1, :flags=>0, :table2=>254,
      #    :gateway=>#<IPAddr: IPv4:10.69.255.253/255.255.255.255>, :oif=>2}>, ...]
      def read_routes(opt=nil, &blk)
        @rtsocket.send_request RTM_GETROUTE, RT.new(opt),
                     NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST
        @rtsocket.receive_until_done(RTM_NEWROUTE, &blk)
      end

      # Return the memoized route table, filtered according to
      # the optional criteria. Examples:
      #    :family => Socket::AF_INET
      #    :table => Netlink::RT_TABLE_DEFAULT
      #    :protocol => Netlink::RTPROT_STATIC
      #    :type => Netlink::RTN_UNICAST
      #    :scope => Netlink::RT_SCOPE_HOST
      #    :flags => Netlink::RTM_F_NOTIFY
      #    :noflags => Netlink::RTM_F_CLONED
      #    :oif => "eth0"
      #    :iif => "eth1"
      def list(filter=nil, &blk)
        @routes = read_routes
        return @routes.each(&blk) unless filter
        return to_enum(:list, filter) unless block_given?
        filter[:oif] = index(filter[:oif]) if filter.has_key?(:oif)
        filter[:iif] = index(filter[:iif]) if filter.has_key?(:iif)
        @routes.each do |o|
          yield o if (!filter[:family] || o.family == filter[:family]) &&
          (!filter[:table] || o.table == filter[:table]) &&
          (!filter[:protocol] || o.protocol == filter[:protocol]) &&
          (!filter[:type] || o.scope == filter[:protocol]) &&
          (!filter[:scope] || o.type == filter[:type]) &&
          (!filter[:flags] || (o.flags & filter[:flags]) == filter[:flags]) &&
          (!filter[:noflags] || (o.flags & filter[:noflags]) == 0) &&
          (!filter[:oif] || o.oif == filter[:oif]) &&
          (!filter[:iif] || o.iif == filter[:iif])
        end
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
      
      def iproute_modify(code, flags, msg) #:nodoc:
        msg = RT.new(msg)
        
        msg.table ||= RT_TABLE_MAIN
        msg.metrics ||= []
        if code != RTM_DELROUTE
          msg.protocol ||= RTPROT_BOOT
          msg.scope ||= RT_SCOPE_UNIVERSE
          msg.type ||= RTN_UNICAST
        else
          msg.scope ||= RT_SCOPE_NOWHERE
        end
        # Note: there are more complex rules in ip/iproute.c for setting defaults

        msg.iif = index(msg.iif) if msg.iif.is_a?(String)
        msg.oif = index(msg.oif) if msg.oif.is_a?(String)

        @rtsocket.cmd code, msg, flags|NLM_F_REQUEST
        clear_cache
      end
    end
  end
end
