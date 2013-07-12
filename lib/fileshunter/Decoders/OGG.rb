module FilesHunter

  module Decoders

    class OGG < BeginPatternDecoder

      BEGIN_PATTERN_OGG = "OggS\x00".force_encoding('ASCII-8BIT')

      # Sorted by the least dominating extension first
      KNOWN_EXTENSIONS = {
        'vorbis'.force_encoding('ASCII-8BIT') => :oga,
        'theora'.force_encoding('ASCII-8BIT') => :ogv
      }

      def get_begin_pattern
        return BEGIN_PATTERN_OGG, { :offset_inc => 5 }
      end

      def decode(offset)
        ending_offset = nil

        cursor = offset
        extensions = [ :ogg, :ogx ] # By default
        while (ending_offset == nil)
          page_type = @data[cursor+5].ord
          # Read the number of segments
          nbr_segments = @data[cursor+26].ord
          # Compute the total size of the payload
          size = 0
          @data[cursor+27..cursor+26+nbr_segments].bytes.each do |segment_size|
            size += segment_size
          end
          cursor += 27 + nbr_segments
          found_relevant_data(extensions)
          if (page_type == 2)
            # We can find whether it is a video file or an audio one
            KNOWN_EXTENSIONS.each do |token, extension|
              extensions.unshift(extension) if (@data[cursor..cursor+size-1].index(token) != nil)
              extensions.delete(:oga) if (extensions.include?(:ogv))
              found_relevant_data(extensions)
            end
          end
          cursor += size
          progress(cursor)
          # Check if a subsequent page is present
          ending_offset = cursor if ((cursor == @end_offset) or (@data[cursor..cursor+4] != BEGIN_PATTERN_OGG))
        end

        return ending_offset
      end

    end

  end

end
