require 'rake/testtask'

ROOT = File.dirname(__FILE__)

Rake::TestTask.new do |t|
  t.verbose = true
  t.test_files = FileList["test/**/t_*.rb"]
end

task :gem do
  sh "gem build netlinkrb.gemspec"
end
