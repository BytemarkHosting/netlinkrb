require 'netlink/message'
require 'netlink/nlsocket'

module Netlink
  ULOG_NL_EVENT = 111  # from ipv4/netfilter/ipt_ULOG.c
  
  # struct ulog_packet_msg
  class UlogPacket < Message
    code ULOG_NL_EVENT
    
    field :mark, :ulong
    field :timestamp_sec, :long
    field :timestamp_usec, :long
    field :hook, :uint
    field :indev_name, :dev_name
    field :outdev_name, :dev_name
    field :data_len, :size_t
    field :prefix, :pattern=>"Z#{ULOG_PREFIX_LEN}", :default=>EMPTY_STRING
    field :mac_len, :uchar
    field :mac, :pattern=>"a#{ULOG_MAC_LEN}", :default=>EMPTY_STRING
    field :payload, :binary

    def after_parse #:nodoc:
      mac.slice!(mac_len..-1) if mac.length > mac_len
      payload.slice!(data_len..-1) if payload.length > mac_len
    end
  end

  module NFLog
    class Socket < NLSocket
      # Create a socket to listen for ulog packets. You must pass :group=>N
      # (where N is 1 to 32) or :groups=>bitmap to listen on multiple groups
      def initialize(opt={})
        unless opt[:groups]
          opt[:groups] = 1 << (opt.fetch(:group) - 1)
        end
        super(opt.merge(:protocol => Netlink::NETLINK_NFLOG))
      end
      
      # Receive packets and yield them to the block
      def dequeue_packets(&blk)
        receive_stream(ULOG_NL_EVENT, &blk)
      end
    end
  end
end
