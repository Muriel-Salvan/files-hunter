module FilesHunter

  module Decoders

    class OGG < BeginPatternDecoder

      BEGIN_PATTERN_OGG = "OggS\x00".force_encoding('ASCII-8BIT')

      def get_begin_pattern
        return BEGIN_PATTERN_OGG, { :offset_inc => 5 }
      end

      def decode(offset)
        ending_offset = nil

        cursor = offset
        while (ending_offset == nil)
          # Read the number of segments
          nbr_segments = @data[cursor+26].ord
          # Compute the total size of the payload
          size = 0
          @data[cursor+27..cursor+26+nbr_segments].bytes.each do |segment_size|
            size += segment_size
          end
          cursor += 27 + nbr_segments + size
          progress(cursor)
          found_relevant_data(:ogg)
          # Check if a subsequent page is present
          if ((cursor == @end_offset) or
              (@data[cursor..cursor+4] != BEGIN_PATTERN_OGG))
            ending_offset = cursor
          end
        end

        return ending_offset
      end

    end

  end

end
