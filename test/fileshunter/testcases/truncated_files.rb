module FilesHunterTest

  module TestCases

    # Test that all our sane files are recognized with their correct extension
    class TruncatedFiles < ::Test::Unit::TestCase

      include FilesHunterTest::Common

      NBR_BYTES_MISSING = 512

      IGNORE_EXTENSIONS = [
        :txt,
        :log,
        :srt,
        :html,
        :xml,
        :rtf,
        :mp3
      ]

      IGNORE_FILES = [
        'CCITT_6.TIF', # Metadata is at the end of the file: unable to detect truncation
        'G4.TIF' # Metadata is at the end of the file: unable to detect truncation
      ]

      Dir.glob("#{FILES_ROOT_PATH}/**/*").each do |file_name|
        if ((!IGNORE_EXTENSIONS.include?(File.extname(file_name)[1..-1].downcase.to_sym)) and
            (!IGNORE_FILES.include?(File.basename(file_name))))

          # Truncate file
          define_method "test_truncated_file_#{file_name.gsub(FILES_ROOT_PATH,'')}" do
            prepare_temp_file(file_name) do |temp_file_name|
              # Insert bytes of garbage before and duplicate
              File.open(temp_file_name, 'wb') do |temp_file|
                File.open(file_name, 'rb') do |file|
                  temp_file.write(file.read(File.size(file_name)-NBR_BYTES_MISSING))
                end
              end
              # Analyze both
              segments = get_cached_segments(file_name)
              temp_segments = segments_analyzer.get_segments(temp_file_name)
              assert_equal 1, temp_segments.size
              assert_equal segments[0].extensions, temp_segments[0].extensions
              assert_equal 0, temp_segments[0].begin_offset
              assert_equal File.size(file_name)-NBR_BYTES_MISSING, temp_segments[0].end_offset
              # Check that metadata is included
              temp_segments[0].metadata.each do |key, value|
                assert_equal segments[0].metadata[key], value
              end
              assert_equal true, temp_segments[0].truncated
              assert_equal false, temp_segments[0].missing_previous_data
            end
          end

        end

      end

    end

  end

end
