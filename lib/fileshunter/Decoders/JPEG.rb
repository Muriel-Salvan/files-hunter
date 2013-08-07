module FilesHunter

  module Decoders

    # JPEG decoder has to be among the last ones to be decoded, as a truncated JPEG followed by other files can consume all files in its truncated data.
    # JPEG files can contain TIFF files

    class JPEG < BeginPatternDecoder

      MARKER_PREFIX = "\xFF".force_encoding(Encoding::ASCII_8BIT)
      END_MARKER = "\xD9".force_encoding(Encoding::ASCII_8BIT)
      MARKERS_WITHOUT_PAYLOAD = [
        "\xD8".force_encoding(Encoding::ASCII_8BIT),
        "\xD9".force_encoding(Encoding::ASCII_8BIT)
      ]
      MARKER_WITH_ENTROPY_DATA = "\xDA".force_encoding(Encoding::ASCII_8BIT)
      MARKER_APP0 = "\xE0".force_encoding(Encoding::ASCII_8BIT)
      MARKER_APP1 = "\xE1".force_encoding(Encoding::ASCII_8BIT)
      MARKER_SOF0 = "\xC0".force_encoding(Encoding::ASCII_8BIT)
      MARKER_SOF3 = "\xC3".force_encoding(Encoding::ASCII_8BIT)
      MARKER_DHT = "\xC4".force_encoding(Encoding::ASCII_8BIT)
      MARKER_SOS = "\xDA".force_encoding(Encoding::ASCII_8BIT)
      MARKER_DQT = "\xDB".force_encoding(Encoding::ASCII_8BIT)
      MARKERS_IGNORED_IN_ENTROPY_DATA = [
        "\x00".force_encoding(Encoding::ASCII_8BIT),
        "\xD0".force_encoding(Encoding::ASCII_8BIT),
        "\xD1".force_encoding(Encoding::ASCII_8BIT),
        "\xD2".force_encoding(Encoding::ASCII_8BIT),
        "\xD3".force_encoding(Encoding::ASCII_8BIT),
        "\xD4".force_encoding(Encoding::ASCII_8BIT),
        "\xD5".force_encoding(Encoding::ASCII_8BIT),
        "\xD6".force_encoding(Encoding::ASCII_8BIT),
        "\xD7".force_encoding(Encoding::ASCII_8BIT),
        "\xFF".force_encoding(Encoding::ASCII_8BIT)
      ]
      MARKERS_IGNORED_IN_ENTROPY_DATA_REGEXP = Regexp.new("#{MARKER_PREFIX}[^#{MARKERS_IGNORED_IN_ENTROPY_DATA.join}]", nil, 'n')

      JFIF_HEADER = "JFIF\x00".force_encoding(Encoding::ASCII_8BIT)
      JFXX_HEADER = "JFXX\x00".force_encoding(Encoding::ASCII_8BIT)
      EXIF_HEADER = "Exif\x00\x00".force_encoding(Encoding::ASCII_8BIT)

      VALID_EXTENSION_CODES = [ 16, 17, 19 ]

      def get_begin_pattern
        return "\xFF\xD8\xFF".force_encoding(Encoding::ASCII_8BIT)
      end

      def decode(offset)
        ending_offset = nil

        cursor = offset + 2
        nbr_segments = 0
        quantisation_tables_id = []
        huffman_ac_tables_id = []
        huffman_dc_tables_id = []
        found_sos = false
        found_sof = false
        while (ending_offset == nil)
          # Here cursor is at the beginning of the next marker
          # Read the 2 next bytes: they should be FF ??
          log_debug "@#{cursor} Decoding next offset: #{@data[cursor..cursor+1].inspect}"
          invalid_data("@#{cursor} - Did not get a valid marker definition: #{@data[cursor..cursor+1].inspect}") if (@data[cursor] != MARKER_PREFIX)
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
            when MARKER_APP0
              # Application specific data
              log_debug "@#{cursor} - Found APP0 marker"
              # Usually used for JFIF
              case @data[cursor+4..cursor+8]
              when JFIF_HEADER
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
              when JFXX_HEADER
                extension_code = @data[cursor+9].ord
                invalid_data("@#{cursor} - Invalid extension code: #{extension_code}") if (!VALID_EXTENSION_CODES.include?(extension_code))
                metadata( :jfxx_metadata => { :extension_code => extension_code } )
              end
            when MARKER_APP1
              # Application specific data
              log_debug "@#{cursor} - Found APP1 marker"
              # Usually used for Exif
              case @data[cursor+4..cursor+9]
              when EXIF_HEADER
                # Read a TIFF file from cursor+10
                require 'fileshunter/Decoders/TIFF'
                invalid_data("@#{cursor} - Invalid TIFF header") if (@data[cursor+10..cursor+13].index(FilesHunter::Decoders::TIFF::BEGIN_PATTERN_TIFF) != 0)
                tiff_decoder = FilesHunter::Decoders::TIFF.new
                tiff_decoder.setup(FilesHunter::get_segments_analyzer, @data, cursor+10, cursor+2+size)
                tiff_decoder.accept_no_image_data
                begin
                  tiff_decoder.find_segments
                rescue InvalidDataError, TruncatedDataError, AccessAfterDataError
                  # Invalid TIFF data
                  invalid_data("@#{cursor} - Invalid TIFF data: #{$!}")
                end
                segments = tiff_decoder.segments_found
                invalid_data("@#{cursor} - No valid TIFF segment found for Exif") if segments.empty?
                invalid_data("@#{cursor} - Not a valid TIFF segment found for Exif. Found #{segments[0].extensions.inspect}.") if (!segments[0].extensions.include?(:tif))
                invalid_data("@#{cursor} - Truncated TIFF segment found for Exif.") if (segments[0].truncated)
                invalid_data("@#{cursor} - TIFF segment (@#{segments[0].begin_offset}) not found at the beginning of Exif (#{cursor+10}).") if (segments[0].begin_offset != cursor+10)
                #invalid_data("@#{cursor} - TIFF segment not ending (#{segments[0].end_offset}) at the end of Exif (#{cursor+2+size}).") if (segments[0].end_offset != cursor+2+size)
                metadata( :exif_metadata => segments[0].metadata )
                found_relevant_data([:jpg, :thm])
              end
            when MARKER_SOF0..MARKER_SOF3
              # SOF: Start of Frame
              log_debug "@#{cursor} - Found SOF marker"
              invalid_data("@#{cursor} - Found several SOF markers") if found_sof
              invalid_data("@#{cursor} - Found a SOF marker after the SOS marker") if found_sos
              found_sof = true
              sample_precision = @data[cursor+4].ord
              invalid_data("@#{cursor} - Invalid sample precision: #{sample_precision}") if ((sample_precision != 8) and (sample_precision != 12))
              image_height = BinData::Uint16be.read(@data[cursor+5..cursor+6])
              image_width = BinData::Uint16be.read(@data[cursor+7..cursor+8])
              metadata(
                :image_height => image_height,
                :image_width => image_width
              )
              nbr_components = @data[cursor+9].ord
              invalid_data("@#{cursor} - Invalid number of components: #{nbr_components}") if (nbr_components == 0)
              # Check that quantisation tables have been defined
              nbr_components.times do |idx_component|
                sampling = @data[cursor+11+idx_component*3].ord
                horizontal_sampling = ((sampling & 0b11110000) >> 4)
                vertical_sampling = (sampling & 0b00001111)
                invalid_data("@#{cursor} - Invalid horizontal sampling: #{horizontal_sampling}") if (horizontal_sampling == 0)
                invalid_data("@#{cursor} - Invalid vertical sampling: #{vertical_sampling}") if (vertical_sampling == 0)
                dqt_id = @data[cursor+12+idx_component*3].ord
                invalid_data("@#{cursor} - Missing quantisation table ID #{dqt_id}") if (!quantisation_tables_id.include?(dqt_id))
              end
            when MARKER_DHT
              # DHT: Define Huffman tables
              log_debug "@#{cursor} - Found DHT marker"
              end_cursor = cursor + 2 + size
              dht_cursor = cursor + 4
              while (dht_cursor < end_cursor)
                header_byte = @data[dht_cursor].ord
                huffman_type = ((header_byte & 0b11110000) >> 4)
                invalid_data("@#{cursor} - Unknown Huffman table type: #{huffman_type}") if (huffman_type > 1)
                if (huffman_type == 0)
                  huffman_dc_table_id = (header_byte & 0b00001111)
                  #invalid_data("@#{cursor} - Huffman DC table id #{huffman_dc_table_id} already defined.") if (huffman_dc_tables_id.include?(huffman_dc_table_id))
                  huffman_dc_tables_id << huffman_dc_table_id
                  log_debug "@#{cursor} - Found Huffman DC table: #{huffman_dc_table_id}"
                else
                  huffman_ac_table_id = (header_byte & 0b00001111)
                  #invalid_data("@#{cursor} - Huffman AC table id #{huffman_ac_table_id} already defined.") if (huffman_ac_tables_id.include?(huffman_ac_table_id))
                  huffman_ac_tables_id << huffman_ac_table_id
                  log_debug "@#{cursor} - Found Huffman AC table: #{huffman_ac_table_id}"
                end
                nbr_elements = 0
                @data[dht_cursor+1..dht_cursor+16].bytes.each do |nbr_element_for_depth|
                  nbr_elements += nbr_element_for_depth
                end
                dht_cursor += 17 + nbr_elements
                invalid_data("@#{dqt_cursor} - End of Huffman table was supposed to be @#{end_cursor}.") if (dht_cursor > end_cursor)
              end
            when MARKER_SOS
              # SOS: Start of Scan
              log_debug "@#{cursor} - Found SOS marker"
              #invalid_data("@#{cursor} - SOS marker begins whereas no Huffman DC table has been defined.") if (huffman_dc_tables_id.empty?)
              #invalid_data("@#{cursor} - SOS marker begins whereas no Huffman AC table has been defined.") if (huffman_ac_tables_id.empty?)
              invalid_data("@#{cursor} - SOS marker begins whereas no quantisation table has been defined.") if (quantisation_tables_id.empty?)
              invalid_data("@#{cursor} - SOS marker begins whereas no SOF marker has been encountered.") if (!found_sof)
              found_sos = true
              nbr_components = @data[cursor+4].ord
              invalid_data("@#{cursor} - Invalid number of components: #{nbr_components}") if (nbr_components == 0)
              nbr_components.times do |idx_component|
                huffman_table_ids = @data[cursor+6+2*idx_component].ord
                huffman_dc_table_id = ((huffman_table_ids & 0b11110000) >> 4)
                huffman_ac_table_id = (huffman_table_ids & 0b00001111)
                #invalid_data("@#{cursor} - Unknown DC Huffman table: #{huffman_dc_table_id}") if (!huffman_dc_tables_id.include?(huffman_dc_table_id))
                #invalid_data("@#{cursor} - Unknown AC Huffman table: #{huffman_ac_table_id}") if (!huffman_ac_tables_id.include?(huffman_ac_table_id))
              end
            when MARKER_DQT
              # DQT: Define quantisation tables
              log_debug "@#{cursor} - Found DQT marker"
              end_cursor = cursor + 2 + size
              dqt_cursor = cursor + 4
              while (dqt_cursor < end_cursor)
                header_byte = @data[dqt_cursor].ord
                precision = ((header_byte & 0b11110000) >> 4)
                quantisation_table_id = (header_byte & 0b00001111)
                invalid_data("@#{cursor} - Quantisation table id #{quantisation_table_id} already defined.") if (quantisation_tables_id.include?(quantisation_table_id))
                quantisation_tables_id << quantisation_table_id
                log_debug "@#{cursor} - Found quantisation table: #{quantisation_table_id}"
                dqt_cursor += 1 + 64*((precision == 0) ? 1 : 2)
                invalid_data("@#{dqt_cursor} - End of quantisation table was supposed to be @#{end_cursor}.") if (dqt_cursor > end_cursor)
              end
            else
              log_debug "@#{cursor} - Found ignored marker: #{c_1.inspect}"
            end
            # Does it have entropy data?
            if (c_1 == MARKER_WITH_ENTROPY_DATA)
              # There is entropy data
              found_relevant_data([:jpg, :thm])
              # Find the next marker that is FF xx, with xx being different than 00, D0..D7 and FF
              cursor = @data.index(MARKERS_IGNORED_IN_ENTROPY_DATA_REGEXP, cursor + 2 + size, 2)
              log_debug "=== Entropy data gets to cursor #{cursor.inspect}"
              truncated_data("@#{cursor} - Truncated entropy data segment", @end_offset) if (cursor == nil)
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
