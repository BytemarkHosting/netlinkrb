module Netlink
  module Route
    # This class allows objects to be created representing the
    # conditions given to the 'list' method
    class BaseFilter #:nodoc:
      def self.filter name, &blk
        define_method "#{name}=" do |matchval|
          @conds << [blk, matchval]
        end
      end
      
      def initialize(h)
        @conds = []
        h.each { |k,v| send "#{k}=", v }
      end
      
      def match(obj)
        !@conds.find { |blk,matchval| !blk[obj,matchval] }
      end
    end

    # Code which is common to all the NETLINK_ROUTE handlers
    class Handler
      def initialize(rtsocket = Netlink::Route::Socket.new)
        @rtsocket = rtsocket
        clear_cache
      end
      
      def index(v)
        @rtsocket.index(v)
      end
      
      def ifname(v)
        @rtsocket.ifname(v)
      end

      # Generic listing and filtering
      def do_list(data, filter, &blk)
        return data.each(&blk) unless filter
        return to_enum(:list, filter) unless block_given?
        fm = self.class::Filter.new(filter)
        data.each { |o| yield o if fm.match(o) }
      end
    end
  end
end
