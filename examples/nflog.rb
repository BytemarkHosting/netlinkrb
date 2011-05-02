LIBDIR = File.expand_path(File.join(File.dirname(__FILE__), '..', 'lib'))
$LOAD_PATH.unshift LIBDIR

require 'pp'
require 'netlink/nflog'

# Example of using Netlink::NFLog to capture all outbound packets
# to TCP port 7551. Use "telnet 127.0.0.1 7551" to test.

#system("iptables -I OUTPUT -j ULOG --ulog-nlgroup 1 -p tcp --destination-port 7551")
nl = Netlink::NFLog::Socket.new(:group => 1)
nl.dequeue_packets do |pkt|
  p pkt
end
