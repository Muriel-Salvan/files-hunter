module FilesHunter

  module Decoders

    class MPG_Video < BeginPatternDecoder

      BEGIN_PATTERN_MPG = "\x00\x00\x01\xBA\x21\x00\x01\x00\x01\x80".force_encoding('ASCII-8BIT')
      END_PATTERN_MPG = "\x00\x00\x01\xB7\x00\x00\x01\xB9".force_encoding('ASCII-8BIT')

      def get_begin_pattern
        return BEGIN_PATTERN_MPG, { :offset_inc => 10 }
      end

      def decode(offset)
        ending_offset = nil

        found_relevant_data(:mpg)
        end_pattern_offset = @data.index(END_PATTERN_MPG, offset + 10)
        log_debug "=== @#{offset} - Found ending offset: #{end_pattern_offset.inspect}"
        truncated_data if ((end_pattern_offset == nil) or (end_pattern_offset + 8 > @end_offset))
        ending_offset = end_pattern_offset + 8

        return ending_offset
      end

    end

  end

end
