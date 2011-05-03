LIBDIR = File.expand_path(File.join(File.dirname(__FILE__), '..', 'lib'))
$LOAD_PATH.unshift LIBDIR

require 'netlink/route'
require 'pp'

nl = Netlink::Route::Socket.new
puts "\n*** Before adding VLAN"
pp nl.if.links(:kind=>"vlan").to_a

puts "\n*** After adding VLAN on lo"
begin
  nl.if.add_vlan(:link=>"lo", :vlan_id=>1234)
rescue Errno::EEXIST
  puts "Already present"
end
pp nl.if.links(:kind=>"vlan").to_a

puts "\n*** After deleting VLANs from lo"
nl.if.delete_vlan(:link=>"lo", :vlan_id=>1234)
pp nl.if.links(:kind=>"vlan").to_a
