module FilesHunterTest

  module TestCases

    # Test that all our sane files are recognized with their correct extension if they are duplicated with garbage
    class DuplicatedFiles < ::Test::Unit::TestCase

      include FilesHunterTest::Common

      GARBAGE_SIZE = 1024

      Dir.glob("#{FILES_ROOT_PATH}/**/*").each do |file_name|

        # Insert garbage before
        define_method "test_duplicated_file_#{file_name.gsub(FILES_ROOT_PATH,'')}" do
          original_data = nil
          File.open(file_name, 'rb') do |file|
            original_data = file.read
          end
          prepare_temp_file(file_name) do |temp_file_name|
            # Insert bytes of garbage before and duplicate
            File.open(temp_file_name, 'wb') do |temp_file|
              temp_file.write("\x01" * GARBAGE_SIZE)
              temp_file.write(original_data)
              temp_file.write("\x01" * GARBAGE_SIZE)
              temp_file.write(original_data)
              temp_file.write("\x01" * GARBAGE_SIZE)
            end
            # Analyze both
            segments = get_cached_segments(file_name)
            temp_segments = segments_analyzer.get_segments(temp_file_name)
            assert_equal 5, temp_segments.size
            assert_equal [:unknown], temp_segments[0].extensions
            assert_equal 0, temp_segments[0].begin_offset
            assert_equal GARBAGE_SIZE, temp_segments[0].end_offset
            assert_equal segments[0].extensions, temp_segments[1].extensions
            assert_equal segments[0].begin_offset+GARBAGE_SIZE, temp_segments[1].begin_offset
            assert_equal segments[0].end_offset+GARBAGE_SIZE, temp_segments[1].end_offset
            assert_equal segments[0].metadata, temp_segments[1].metadata
            assert_equal segments[0].truncated, temp_segments[1].truncated
            assert_equal segments[0].missing_previous_data, temp_segments[1].missing_previous_data
            assert_equal [:unknown], temp_segments[2].extensions
            assert_equal GARBAGE_SIZE+segments[0].end_offset, temp_segments[2].begin_offset
            assert_equal 2*GARBAGE_SIZE+segments[0].end_offset, temp_segments[2].end_offset
            assert_equal segments[0].extensions, temp_segments[3].extensions
            assert_equal 2*GARBAGE_SIZE+segments[0].end_offset, temp_segments[3].begin_offset
            assert_equal 2*GARBAGE_SIZE+2*segments[0].end_offset, temp_segments[3].end_offset
            assert_equal segments[0].metadata, temp_segments[3].metadata
            assert_equal segments[0].truncated, temp_segments[3].truncated
            assert_equal segments[0].missing_previous_data, temp_segments[3].missing_previous_data
            assert_equal [:unknown], temp_segments[4].extensions
            assert_equal 2*GARBAGE_SIZE+2*segments[0].end_offset, temp_segments[4].begin_offset
            assert_equal 3*GARBAGE_SIZE+2*segments[0].end_offset, temp_segments[4].end_offset
          end
        end

      end

    end

  end

end
