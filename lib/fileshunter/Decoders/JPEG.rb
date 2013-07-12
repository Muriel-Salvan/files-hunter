module FilesHunter

  module Decoders

    class JPEG < BeginPatternDecoder

      END_MARKER = "\xD9"
      MARKERS_WITHOUT_PAYLOAD = [
        "\xD8",
        "\xD9"
      ]
      MARKER_WITH_ENTROPY_DATA = "\xDA"
      MARKERS_IGNORED_IN_ENTROPY_DATA = [
        "\x00",
        "\xD0",
        "\xD1",
        "\xD2",
        "\xD3",
        "\xD4",
        "\xD5",
        "\xD6",
        "\xD7",
        "\xFF"
      ]
      MARKERS_IGNORED_IN_ENTROPY_DATA_REGEXP = Regexp.new("\xFF[^#{MARKERS_IGNORED_IN_ENTROPY_DATA.join}]".force_encoding(Encoding::ASCII_8BIT))

      def get_begin_pattern
        return "\xFF\xD8\xFF".force_encoding(Encoding::ASCII_8BIT)
      end

      def decode(offset)
        ending_offset = nil

        cursor = offset + 2
        while (ending_offset == nil)
          # Here cursor is at the beginning of the next marker
          # Read the 2 next bytes: they should be FF ??
          log_debug "=== Cursor is @#{cursor}"
          log_debug "=== Decoding next offset: #{@data[cursor..cursor+1].inspect}"
          invalid_data("@#{cursor} - Did not get a valid marker definition: #{@data[cursor..cursor+1].inspect}") if (@data[cursor] != "\xFF")
          c_1 = @data[cursor+1]
          invalid_data("@#{cursor} - Invalid marker: #{c_1.ord}") if (c_1.ord < 192)
          # Does this marker have a payload?
          if (MARKERS_WITHOUT_PAYLOAD.include?(c_1))
            # No payload
            log_debug "=== No payload"
            # Check if we arrived at the end
            ending_offset = cursor+2 if (c_1 == END_MARKER)
            # Get to the next bytes
            cursor += 2
          else
            # There is a payload
            # Read its length
            size = BinData::Uint16be.read(@data[cursor+2..cursor+3])
            log_debug "=== Payload of size #{size}"
            # Does it have entropy data?
            if (c_1 == MARKER_WITH_ENTROPY_DATA)
              # There is entropy data
              found_relevant_data([:jpg, :thm])
              # Find the next marker that is FF xx, with xx being different than 00, D0..D7 and FF
              cursor = @data.index(MARKERS_IGNORED_IN_ENTROPY_DATA_REGEXP, cursor + 2 + size, 2)
              log_debug "=== Entropy data gets to cursor #{cursor}"
              truncated_data("@#{cursor} - Truncated entropy data segment") if (cursor == nil)
            else
              # No entropy data: just get to the next segment
              cursor += 2 + size
            end
          end
          progress(cursor)
        end

        return ending_offset
      end

    end

  end

end
