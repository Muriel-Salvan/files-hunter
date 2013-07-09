module FilesHunter

  module Decoders

    class RIFF < BeginPatternDecoder

      BEGIN_PATTERN_RIFF = 'RIFF'.force_encoding('ASCII-8BIT')
      BEGIN_PATTERN_RIFX = 'RIFX'.force_encoding('ASCII-8BIT')
      BEGIN_PATTERN_JUNK = 'JUNK'.force_encoding('ASCII-8BIT')
      ACCEPTABLE_RIFF = [
        BEGIN_PATTERN_RIFF,
        BEGIN_PATTERN_RIFX,
        BEGIN_PATTERN_JUNK
      ]
      RIFF_TYPES = {
        'WAVE' => :wav,
        'AVI ' => :avi
      }

      def get_begin_pattern
        return [ BEGIN_PATTERN_RIFF, BEGIN_PATTERN_RIFX ], { :offset_inc => 4 }
      end

      def decode(offset)
        ending_offset = nil

        cursor = offset
        found_RIFF = false
        while (ending_offset == nil)
          name = @data[cursor..cursor+3]
          invalid_data("@#{cursor} - Unknown RIFF #{name}") if (!ACCEPTABLE_RIFF.include?(name))
          size = ((name == BEGIN_PATTERN_RIFF) or (name == BEGIN_PATTERN_JUNK)) ? BinData::Uint32le.read(@data[cursor+4..cursor+7]) : BinData::Uint32be.read(@data[cursor+4..cursor+7])
          size += 1 if size.odd?
          log_debug "@#{cursor} - Found RIFF segment #{name} of size #{size}"
          if (name == BEGIN_PATTERN_JUNK)
            if (found_RIFF)
              # We stop at the end of this chunk
              ending_offset = cursor + size + 8
            end
          else
            if (found_RIFF)
              # Oups we are getting on a second RIFF file
              ending_offset = cursor
            else
              found_RIFF = true
              # Determine the file type
              c_8_11 = @data[cursor+8..cursor+11]
              extension = RIFF_TYPES[c_8_11]
              invalid_data("@#{cursor} - Unknown RIFF extension: #{c_8_11}") if (extension == nil)
              found_relevant_data(extension)
              ending_offset = cursor + size + 8 if (cursor + size + 8 == @end_offset)
            end
          end
          cursor += size + 8
          progress(cursor)
        end

        return ending_offset
      end

    end

  end

end
