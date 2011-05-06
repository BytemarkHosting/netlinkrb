LIBDIR = File.expand_path(File.join(File.dirname(__FILE__), '..', 'lib'))
$LOAD_PATH.unshift LIBDIR

require 'linux/netlink/route'
require 'pp'

ip = Linux::Netlink::Route::Socket.new
puts "\n*** Before adding VLAN"
pp ip.vlan.list(:link=>"lo").to_a

puts "\n*** After adding VLAN on lo"
begin
  ip.vlan.add(:link=>"lo", :vlan_id=>1234)
rescue Errno::EEXIST
  puts "Already present"
end
pp ip.vlan.list(:link=>"lo").to_a

puts "\n*** After deleting VLAN from lo"
ip.vlan.delete(:link=>"lo", :vlan_id=>1234)
pp ip.vlan.list(:link=>"lo").to_a
