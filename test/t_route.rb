require File.join(File.dirname(__FILE__), 'test_helper')
require 'linux/netlink/route'

# Note: multiple sockets bound to the same PID seem to cause timeout problems.
# (Should we use different algorithm for generating the PID? PID + seq?)
$ip ||= Linux::Netlink::Route::Socket.new

#
# Ruby 1.8.7 appears to lack the KeyError constant.
#
if RUBY_VERSION == "1.8.7"
  KeyError = IndexError
end

class TestAddr < Test::Unit::TestCase
  context "With netlink route socket" do
    setup do
      @ip = $ip
      @ifname = nil
    end

    teardown do
      begin
        delete_test_interface(@ifname)
      rescue KeyError, IndexError
        # Do nothing
      end
    end

    test "Read link type" do
      assert_equal Linux::ARPHRD_LOOPBACK, @ip.link["lo"].type
    end

    def create_test_interface(ifname = "test_#{$$}")
      begin
        @ip.link.add(
          :ifname => ifname,
          :linkinfo => Linux::Netlink::LinkInfo.new(
            :kind => "dummy"
          )
        )
      rescue Errno::EOPNOTSUPP
        # Ugh, fall back to eth0
        ifname = "eth0"
      rescue Errno::EPERM => err
        do_skip err.to_s
      end

      return ifname
    end

    def set_interface_up(ifname)
      link = @ip.link.list.find{|l| l.ifname == ifname}
      return unless link.linkinfo and "dummy" == link.linkinfo.kind

      #
      # Bring the link up
      #
      @ip.link.change(
        :index => link.index,
        :flags => link.flags | Linux::IFF_UP | Linux::IFF_RUNNING
      )

      link = @ip.link.list.find{|l| l.ifname == ifname}

      assert_equal(Linux::IFF_UP, link.flags & Linux::IFF_UP, "Link does not have the IFF_UP flag set")
      assert_equal(Linux::IFF_RUNNING, link.flags & Linux::IFF_RUNNING, "Link does not have the IFF_RUNNING flag set") 
    end

    def set_interface_down(ifname)
      link = @ip.link.list.find{|l| l.ifname == ifname}

      return if link.nil?
      return unless link.linkinfo and "dummy" == link.linkinfo.kind
      return unless link.flags == (link.flags | Linux::IFF_UP | Linux::IFF_RUNNING)

      #
      # Bring the link up
      #
      @ip.link.change(
        :index => link.index,
        :flags => link.flags & ~Linux::IFF_UP & ~Linux::IFF_RUNNING
      )

      link = @ip.link.list.find{|l| l.ifname == ifname}

      assert_equal(0, link.flags & Linux::IFF_UP, "Link still has the IFF_UP flag set")
      assert_equal(0, link.flags & Linux::IFF_RUNNING, "Link still has the IFF_RUNNING flag set") 
    end

    def delete_test_interface(ifname) 
      unless @ip.link[ifname] and @ip.link[ifname].linkinfo and "dummy" == @ip.link[ifname].linkinfo.kind
        return nil
      end

      begin
        set_interface_down(ifname)
      ensure
        @ip.link.delete(:index => ifname)
      end
    end

    def do_skip(msg)
      if self.respond_to?(:skip)
        skip msg
      else
        puts "Skipping #{self.method_name} -- #{msg}"
      end
      return nil
    end

    test "Add and remove dummy interface" do
      @ifname = create_test_interface
      return if @ifname.nil?

      unless @ip.link[@ifname] and @ip.link[@ifname].linkinfo and "dummy" == @ip.link[@ifname].linkinfo.kind
        return do_skip("Could not create dummy interface")
      end

      delete_test_interface(@ifname)
    end
    
    def addrlist(opt = {:index=>"lo"})
      res = @ip.addr.list(opt).map { |x| x.address.to_s }.sort
    end

    def add_and_remove_addr(testaddr, pfx)
      @ifname = create_test_interface
      return if @ifname.nil?

      addrs1 = addrlist({:index => @ifname})
      assert !addrs1.include?(testaddr)

      @ip.addr.add(:index=>@ifname, :local=>testaddr, :prefixlen=>pfx)
      assert_raises(Errno::EEXIST) {
        @ip.addr.add(:index=>@ifname, :local=>testaddr, :prefixlen=>pfx)
      }

      addrs2 = addrlist({:index => @ifname})
      assert addrs2.include?(testaddr), "#{addrs2.inspect} doesn't include #{testaddr}"
      
      @ip.addr.delete(:index=>@ifname, :local=>testaddr, :prefixlen=>pfx)
      
      addrs3 = addrlist({:index => @ifname})
      assert_equal addrs1, addrs3
    end

    test "Read all addresses" do
      a = addrlist
      assert a.include?("127.0.0.1")
      assert a.include?("::1")
    end
    
    test "Read v4 addresses only" do
      a = addrlist(:index=>"lo", :family=>Socket::AF_INET)
      assert a.include?("127.0.0.1")
      assert !a.include?("::1")
    end

    test "Read v6 addresses only" do
      a = addrlist(:index=>"lo", :family=>Socket::AF_INET6)
      assert !a.include?("127.0.0.1")
      assert a.include?("::1")
    end

    test "Add and remove V4 address" do
      add_and_remove_addr("127.1.0.0", 32)
    end
  
    test "Add and remove V6 address" do
      add_and_remove_addr("2001:dead:beef::1", 64)
    end

    def vlanlist(ifname)
      @ip.vlan.list(:link=>ifname).map { |x| x.linkinfo.data.id }
    end
  
    test "Add and remove vlan" do
      @ifname = create_test_interface
      return if @ifname.nil?

      vlans1 = vlanlist(@ifname)
      assert !vlans1.include?(1234)

      @ip.vlan.add(:link=>@ifname, :vlan_id=>1234)

      vlans2 = vlanlist(@ifname)
      assert vlans2.include?(1234)

      @ip.vlan.delete(:link=>@ifname, :vlan_id=>1234)

      vlans3 = vlanlist(@ifname)
      assert_equal vlans1, vlans3
    end

    def routes
      @ip.route.list(:table=>Linux::RT_TABLE_MAIN).map { |x| [x.dst.to_s, x.dst_len, x.oif] }
    end
    
    def v4routes
      @ip.route.list(:table=>Linux::RT_TABLE_MAIN).select{|x| Socket::AF_INET == x.family}.
        map { |x| [x.dst.to_s, x.dst_len, x.oif] }
    end

    test "We have a V4 default route" do
      # note that kernel doesn't send us rtattr dst 0.0.0.0, so it shows as nil
      assert v4routes.find{|x| x[0] == "" and x[1] == 0}
    end
    
    def add_and_remove_route(info)
      @ifname = create_test_interface
      return if @ifname.nil?

      set_interface_up(@ifname) 

      info[:oif] = @ifname
      ifidx = @ip.link.list.find{|x| x.ifname == info[:oif]}.index

      assert_equal 0, routes.select { |x| x == [info[:dst], info[:dst_len], ifidx] }.size

      @ip.route.add(info)
      assert_equal 1, routes.select { |x| x == [info[:dst], info[:dst_len], ifidx] }.size

      @ip.route.delete(info)      
      assert_equal 0, routes.select { |x| x == [info[:dst], info[:dst_len], ifidx] }.size
    end

    test "Add and remove V4 route" do
      add_and_remove_route(:dst=>"127.1.0.1", :dst_len=>32) 
    end

    test "Add and remove V6 route" do
      add_and_remove_route(:dst=>"fc10::", :dst_len=>64)
    end
  end
end
