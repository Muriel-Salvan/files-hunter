module FilesHunterTest

  module TestCases

    # Test that all our sane files are recognized with their correct extension
    class SaneFiles < ::Test::Unit::TestCase

      include FilesHunterTest::Common

      Dir.glob("#{FILES_ROOT_PATH}/**/*").each do |file_name|
        define_method "test_sane_file_#{file_name.gsub(FILES_ROOT_PATH,'')}" do
          segments = segments_analyzer.get_segments(file_name)
          assert_equal 1, segments.size
          assert_equal File.extname(file_name)[1..-1].downcase.to_sym, segments[0].extensions[0]
          assert_equal false, segments[0].truncated
        end
      end

    end

  end

end
