require File.join(File.dirname(__FILE__), 'test_helper')
require 'linux/netlink/route'

# Note: multiple sockets bound to the same PID seem to cause timeout problems.
# (Should we use different algorithm for generating the PID? PID + seq?)
$ip ||= Linux::Netlink::Route::Socket.new

class TestAddr < Test::Unit::TestCase
  context "With netlink route socket" do
    setup do
      @ip = $ip
    end

    test "Read link type" do
      assert_equal Linux::ARPHRD_LOOPBACK, @ip.link["lo"].type
    end
    
    def addrlist(opt = {:index=>"lo"})
      res = @ip.addr.list(opt).map { |x| x.address.to_s }.sort
    end

    def add_and_remove_addr(testaddr, pfx)
      begin
        @ip.addr.delete(:index=>"lo", :local=>testaddr, :prefixlen=>pfx)
      rescue Errno::EADDRNOTAVAIL
      end
      
      addrs1 = addrlist
      assert !addrs1.include?(testaddr)

      @ip.addr.add(:index=>"lo", :local=>testaddr, :prefixlen=>pfx)
      assert_raises(Errno::EEXIST) {
        @ip.addr.add(:index=>"lo", :local=>testaddr, :prefixlen=>pfx)
      }

      addrs2 = addrlist
      assert addrs2.include?(testaddr), "#{addrs2.inspect} doesn't include #{testaddr}"
      
      @ip.addr.delete(:index=>"lo", :local=>testaddr, :prefixlen=>pfx)
      
      addrs3 = addrlist
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
      add_and_remove_addr("1.2.3.4", 32)
    end
  
    test "Add and remove V6 address" do
      add_and_remove_addr("2001:dead:beef::1", 64)
    end

    def vlanlist
      @ip.vlan.list(:link=>"lo").map { |x| x.linkinfo.data.id }
    end
  
    # FIXME: On 10.04.2 LTS (32 and 64 bit) this gives Errno::EOPNOTSUPP; but
    #    ip link add link lo type vlan id 1234
    #    ip link delete vlan0
    # both work fine.
    test "Add and remove vlan" do
      begin
        @ip.vlan.delete(:link=>"lo", :vlan_id=>1234)
      rescue Errno::ENODEV
      end

      vlans1 = vlanlist
      assert !vlans1.include?(1234)

      @ip.vlan.add(:link=>"lo", :vlan_id=>1234)

      vlans2 = vlanlist
      assert vlans2.include?(1234)

      @ip.vlan.delete(:link=>"lo", :vlan_id=>1234)

      vlans3 = vlanlist
      assert_equal vlans1, vlans3
    end

    def routes
      @ip.route.list(:table=>Linux::RT_TABLE_MAIN).map { |x| [x.dst.to_s, x.dst_len] }
    end
    
    test "We have a V4 default route" do
      # note that kernel doesn't send us rtattr dst 0.0.0.0, so it shows as nil
      assert_equal [["",0]], routes.select { |x| x == ["",0] }
    end
    
    def add_and_remove_route(info)
      begin
        @ip.route.delete(info)
      rescue Errno::ESRCH
      end
      
      assert_equal 0, routes.select { |x| x == [info[:dst], info[:dst_len]] }.size

      @ip.route.add(info)
      assert_equal 1, routes.select { |x| x == [info[:dst], info[:dst_len]] }.size

      @ip.route.delete(info)      
      assert_equal 0, routes.select { |x| x == [info[:dst], info[:dst_len]] }.size
    end

    test "Add and remove V4 route" do
      add_and_remove_route(:oif=>"lo", :dst=>"1.2.3.4", :dst_len=>32, :gateway=>"127.0.0.1")
    end

    test "Add and remove V6 route" do
      add_and_remove_route(:oif=>"lo", :dst=>"2001:f000:baaa::", :dst_len=>64)
    end
  end
end
