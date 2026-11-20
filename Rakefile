desc 'The unit tests, as CI runs them'
task :test do
  ruby 'test/run_unit.rb'
end

desc 'The functional tests, as CI runs them'
task :functional do
  ruby 'test/run_functional.rb'
end

task default: %i[test functional]
