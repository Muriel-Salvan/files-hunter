module FilesHunter

  module Decoders

    class M2V < BeginPatternDecoder

      BEGIN_PATTERN_M2V = "\x00\x00\x01\xBA\x44\x00\x04\x00\x14\x01".force_encoding('ASCII-8BIT')
      END_PATTERN_M2V = "\x00\x00\x01\xB9".force_encoding('ASCII-8BIT')

      def get_begin_pattern
        return BEGIN_PATTERN_M2V, { :offset_inc => 10 }
      end

      def decode(offset)
        ending_offset = nil

        found_relevant_data(:m2v)
        end_pattern_offset = @data.index(END_PATTERN_M2V, offset + 10)
        log_debug "=== @#{offset} - Found ending offset: #{end_pattern_offset.inspect}"
        truncated_data if ((end_pattern_offset == nil) or (end_pattern_offset + 4 > @end_offset))
        ending_offset = end_pattern_offset + 4

        return ending_offset
      end

    end

  end

end
