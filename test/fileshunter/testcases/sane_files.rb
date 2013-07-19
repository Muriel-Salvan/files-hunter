module FilesHunterTest

  module TestCases

    # Test that all our sane files are recognized with their correct extension
    class SaneFiles < ::Test::Unit::TestCase

      include FilesHunterTest::Common

      Dir.glob("#{FILES_ROOT_PATH}/**/*").each do |file_name|
        define_method "test_sane_file_#{file_name.gsub(FILES_ROOT_PATH,'')}" do
          segments = segments_analyzer.get_segments(file_name)
          assert_equal 1, segments.size
          assert segments[0].extensions.include?(File.extname(file_name)[1..-1].downcase.to_sym)
          assert_equal false, segments[0].truncated
          assert_equal false, segments[0].missing_previous_data
        end
      end

    end

  end

end
