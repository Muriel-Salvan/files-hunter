require 'test/unit'

activate_debug = ARGV.delete('--debug')

root_path = File.expand_path("#{File.dirname(__FILE__)}/..")

# Add the test directory to the current load path
$: << "#{root_path}/test"
# And the lib one too
$: << "#{root_path}/lib"
$: << "#{root_path}/ext"

# Require the main library
require 'fileshunter'

activate_log_debug(true) if activate_debug

# Load test files to execute
require 'fileshunter/common'
require 'fileshunter/testcases/sane_files'
require 'fileshunter/testcases/sane_files_with_garbage'
require 'fileshunter/testcases/duplicated_files'
require 'fileshunter/testcases/truncated_files'
