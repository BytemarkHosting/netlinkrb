# encoding: utf-8

lib = File.expand_path("../lib", __FILE__)
$:.unshift lib unless $:.include? lib

Gem::Specification.new do |s|
  s.name = "netlinkrb"
  s.version = "0.16"
  s.platform = Gem::Platform::RUBY
  s.authors = ["Brian Candler", "Matthew Bloch", "Patrick Cherry", "Alex Young", "Nicholas Thomas"]
  s.email = ["matthew@bytemark.co.uk"]
  s.summary = "Interface to Linux' Netlink API"
  s.description = "Ruby native interface to the Netlink API which avoids shelling out to command-line tools as much as possible."
  s.files = Dir["{lib,examples}/**/*"] + %w{README}
  s.require_path = "lib"
  s.add_dependency "ffi"
end
