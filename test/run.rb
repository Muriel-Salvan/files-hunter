require 'test/unit'

root_path = File.expand_path("#{File.dirname(__FILE__)}/..")

# Add the test directory to the current load path
$: << "#{root_path}/test"
# And the lib one too
$: << "#{root_path}/lib"
$: << "#{root_path}/ext"

# Require the main library
require 'fileshunter'

# Load test files to execute
require 'fileshunter/common'
require 'fileshunter/testcases/sane_files'
