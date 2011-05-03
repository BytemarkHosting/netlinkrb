require 'netlink/route'

module Netlink
  module Route
    class VlanHandler
      def initialize(rtsocket = Netlink::Route::Socket.new)
        @rtsocket = rtsocket
      end
      
      def index(v)
        @rtsocket.index(v)
      end
      
      def list(filter={}, &blk)
        @rtsocket.links.list(filter.merge(:kind=>"vlan"))
      end
      alias :each :list
            
      # Higher-level API to manipulate VLAN interface.
      #    nl.vlans.add(
      #      :link=>"lo",
      #      :vlan_id=>1234,
      #      :vlan_flags=>Netlink::VLAN_FLAG_LOOSE_BINDING,
      #      :vlan_mask=>0xffffffff
      #    )
      def add(opt)
        @rtsocket.links.add(vlan_options(opt))
      end
      
      def change(opt)
        @rtsocket.links.change(vlan_options(opt))
      end
      
      def replace(opt)
        @rtsocket.links.replace(vlan_options(opt))
      end
      
      # Delete vlan given :link and :vlan_id. If you want to delete
      # by :index then call links.delete instead.
      def delete(opt)
        raise "Missing vlan_id" unless opt[:vlan_id]
        raise "Missing link" unless opt[:link]
        link = list(:link=>opt[:link]).find { |l|
            l.linkinfo.data &&
            l.linkinfo.data.id == opt[:vlan_id]
        }
        raise Errno::ENODEV unless link
        @rtsocket.links.delete(link.index)
      end

      def vlan_options(orig) #:nodoc:
        opt = orig.dup
        opt[:link] = index(opt.fetch(:link))
        li = opt[:linkinfo] ||= LinkInfo.new
        li.kind = "vlan"
        li.data ||= VlanInfo.new
        li.data.id = opt.delete(:vlan_id) if opt.has_key?(:vlan_id)
        if opt.has_key?(:vlan_flags)
          li.data.flags ||= VlanFlags.new(:flags => opt.delete(:vlan_flags))
          li.data.flags.mask = opt.delete(:vlan_mask) if opt.has_key?(:vlan_mask)
        end
        li.data.egress_qos = opt.delete(:egress_qos) if opt.has_key?(:egress_qos)
        li.data.ingress_qos = opt.delete(:ingress_qos) if opt.has_key?(:ingress_qos)
        opt
      end
    end
  end
end
