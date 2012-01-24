require 'rake/testtask'

ROOT = File.dirname(__FILE__)

Rake::TestTask.new do |t|
  t.verbose = true
  t.test_files = FileList["test/**/t_*.rb"]
end

desc "Create the size_t size macro for c_struct"
file 'lib/linux/c_struct_sizeof_size_t.rb' do |t|
  begin
    sz = Integer(`echo __SIZEOF_SIZE_T__ | /usr/bin/gcc -E -P -`)
    File.open(t.name, 'w+') do |fh|
      fh.puts "module Linux ; class CStruct ; SIZEOF_SIZE_T = #{sz} ; end ; end"
    end
  rescue
    rm_f t.name
  end
end

desc "Package a gem"
task :gem do 
  #
  # FIXME. If using a gem, fall back on GCC to determine sizeof size_t.
  #
  rm_f "lib/linux/c_struct_sizeof_size_t.rb"
  sh "gem build netlinkrb.gemspec"
end

desc "clean up"
task :clean do
  rm_f "lib/linux/c_struct_sizeof_size_t.rb"
end
