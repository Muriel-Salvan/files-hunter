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

      VALID_EXTENSION_CODES = [ 16, 17, 19 ]

      def get_begin_pattern
        return "\xFF\xD8\xFF".force_encoding(Encoding::ASCII_8BIT)
      end

      def decode(offset)
        ending_offset = nil

        cursor = offset + 2
        nbr_segments = 0
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
            # Get to the next bytes
            cursor += 2
            # Check if we arrived at the end
            ending_offset = cursor if (c_1 == END_MARKER)
          else
            # There is a payload
            # Read its length
            size = BinData::Uint16be.read(@data[cursor+2..cursor+3])
            log_debug "=== Payload of size #{size}"
            case c_1
            when "\xE0"
              # Application specific data
              # Usually used for JFIF
              case @data[cursor+4..cursor+8]
              when "JFIF\x00"
                invalid_data("@#{cursor} - Invalid size for JFIF marker: #{size}") if (size < 16)
                version_major = @data[cursor+9].ord
                version_minor = @data[cursor+10].ord
                units = @data[cursor+11].ord
                invalid_data("@#{cursor} - Invalid units: #{units}") if (units > 2)
                width = BinData::Uint16be.read(@data[cursor+12..cursor+13])
                invalid_data("@#{cursor} - Invalid width: #{width}") if (width == 0)
                height = BinData::Uint16be.read(@data[cursor+14..cursor+15])
                invalid_data("@#{cursor} - Invalid height: #{height}") if (height == 0)
                jfif_metadata = {
                  :version_major => version_major,
                  :version_minor => version_minor,
                  :units => units,
                  :width => width,
                  :height => height
                }
                if (size > 16)
                  width_thumb = BinData::Uint16be.read(@data[cursor+16..cursor+17])
                  height_thumb = BinData::Uint16be.read(@data[cursor+18..cursor+19])
                  jfif_metadata.merge!(
                    :width_thumb => width_thumb,
                    :height_thumb => height_thumb
                  )
                end
                metadata( :jfif_metadata => jfif_metadata )
              when "JFXX\x00"
                extension_code = @data[cursor+9].ord
                invalid_data("@#{cursor} - Invalid extension code: #{extension_code}") if (!VALID_EXTENSION_CODES.include?(extension_code))
                metadata( :jfxx_metadata => { :extension_code => extension_code } )
              end
            when "\xE1"
              # Application specific data
              # Usually used for Exif
              case @data[cursor+4..cursor+9]
              when "Exif\x00\x00"
                # Read a TIFF file from cursor+10
                metadata( :exif_metadata => {

                } )
              end
            end
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
          nbr_segments += 1
          progress(cursor)
        end
        metadata( :nbr_segments => nbr_segments )

        return ending_offset
      end

    end

  end

end
