module FilesHunter

  module Decoders

    class MP3 < BeginPatternDecoder

      BEGIN_PATTERN_ID3V1 = 'TAG'.force_encoding(Encoding::ASCII_8BIT)
      BEGIN_PATTERN_ID3V1E = 'TAG+'.force_encoding(Encoding::ASCII_8BIT)
      BEGIN_PATTERN_ID3V2 = 'ID3'.force_encoding(Encoding::ASCII_8BIT)
      BEGIN_PATTERN_APEV2 = 'APETAGEX'.force_encoding(Encoding::ASCII_8BIT)
      BEGIN_PATTERN_MP3 = Regexp.new("(\xFF[\xE2-\xFF][\x00-\xEF]|#{BEGIN_PATTERN_ID3V2}|#{BEGIN_PATTERN_APEV2})", nil, 'n')

      BITRATE_INDEX = [
        [ 32,  32,  32,  32,  8 ],
        [ 64,  48,  40,  48,  16 ],
        [ 96,  56,  48,  56,  24 ],
        [ 128, 64,  56,  64,  32 ],
        [ 160, 80,  64,  80,  40 ],
        [ 192, 96,  80,  96,  48 ],
        [ 224, 112, 96,  112, 56 ],
        [ 256, 128, 112, 128, 64 ],
        [ 288, 160, 128, 144, 80 ],
        [ 320, 192, 160, 160, 96 ],
        [ 352, 224, 192, 176, 112 ],
        [ 384, 256, 224, 192, 128 ],
        [ 416, 320, 256, 224, 144 ],
        [ 448, 384, 320, 256, 160 ]
      ]
      SAMPLE_RATE_INDEX = [
        [ 44100, 22050, 11025 ],
        [ 48000, 24000, 12000 ],
        [ 32000, 16000, 8000 ]
      ]

      MIN_ACCEPTABLE_TIME_MS = 1000

      MAX_ID3V2_FRAME_SIZE = 256

      APE_ITEM_KEY_TERMINATOR = "\x00".force_encoding(Encoding::ASCII_8BIT)

      ID3V2_PADDING_CHAR = "\x00".force_encoding(Encoding::ASCII_8BIT)

      def get_begin_pattern
        return BEGIN_PATTERN_MP3, { :max_regexp_size => 8 }
      end

      def check_begin_pattern(begin_pattern_offset, pattern_index)
        if (@data[begin_pattern_offset] == "\xFF")
          header_bytes = @data[begin_pattern_offset+1..begin_pattern_offset+3].bytes.to_a
          return (((header_bytes[0] & 24) != 16) and
                  ((header_bytes[0] & 6) != 0) and
                  ((header_bytes[1] & 12) != 12) and
                  ((header_bytes[2] & 3) != 2))
        else
          return true
        end
      end

      def decode(offset)
        ending_offset = nil

        cursor = offset
        nbr_ms = 0
        valid = false
        while (ending_offset == nil)
          #log_debug "=== @#{cursor} - Reading what's here"
          c_0_2 = @data[cursor..cursor+2]
          if (c_0_2 == BEGIN_PATTERN_ID3V1)
            if (@data[cursor..cursor+3] == BEGIN_PATTERN_ID3V1E)
              log_debug "=== @#{cursor} - Found ID3v1 extended tag"
              metadata( :id3v1e_metadata => {
                :title => @data[cursor+4..cursor+63],
                :artist => @data[cursor+64..cursor+123],
                :album => @data[cursor+124..cursor+183],
                :speed => @data[cursor+184].ord,
                :genre => @data[cursor+185..cursor+214],
                :start_time => @data[cursor+215..cursor+220],
                :end_time => @data[cursor+221..cursor+226]
              } )
              cursor += 227
            else
              # Just met an ID3v1 tag: skip 128 bytes
              log_debug "=== @#{cursor} - Found ID3v1 tag"
              metadata( :id3v1_metadata => {
                :title => @data[cursor+3..cursor+32],
                :artist => @data[cursor+33..cursor+62],
                :album => @data[cursor+63..cursor+92],
                :year => @data[cursor+93..cursor+96],
                :comments => @data[cursor+97..cursor+126],
                :genre => @data[cursor+127].ord
              } )
              cursor += 128
              # Current MP3 is finished: id3v1 is forcefully at the end
              ending_offset = cursor
            end
          elsif (c_0_2 == BEGIN_PATTERN_ID3V2)
            # Just met an ID3v2 tag
            log_debug "=== @#{cursor} - Found ID3v2 tag"
            invalid_data("@#{cursor} - Invalid ID3v2 header") if ((@data[cursor+3].ord == 255) or (@data[cursor+4].ord == 255))
            # Compute the tag's size
            size = 10 # Header
            @data[cursor+6..cursor+9].bytes.each_with_index do |byte, idx|
              invalid_data("@#{cursor} - Invalid ID3v2 header in size specification (#{idx})") if (byte >= 128)
              size += (byte << ((8*(3-idx))-3+idx))
            end
            # Is there a footer?
            size += 10 if ((@data[cursor+5].ord & 16) == 16)
            cursor_end = cursor + size
            cursor += 10
            # Check if following is an extended header
            padding_size = 0
            extended_header_size = BinData::Uint32be.read(@data[cursor..cursor+3])
            if ((extended_header_size == 6) or
                (extended_header_size == 10))
              # There is an extended header
              extended_header_flags = BinData::Uint16be.read(@data[cursor+4..cursor+5])
              invalid_data("@#{cursor} - Invalid extended header flags.") if ((extended_header_flags & 0b01111111_11111111) != 0)
              has_crc = ((extended_header_flags & 0b10000000_00000000) != 0)
              invalid_data("@#{cursor} - Extended header declared size and CRC flag do not match.") if (((extended_header_size == 10) and (!has_crc)) or ((extended_header_size == 6) and (has_crc)))
              padding_size = BinData::Uint32be.read(@data[cursor+6..cursor+9])
              cursor += 10
              cursor += 4 if has_crc
            end
            # Read all frames
            id3v2_metadata = {}
            while ((cursor < cursor_end) and
                   (@data[cursor] != ID3V2_PADDING_CHAR))
              # We are on a frame
              frame_id = @data[cursor..cursor+3]
              frame_size = BinData::Uint32be.read(@data[cursor+4..cursor+7])
              frame_flags = BinData::Uint16be.read(@data[cursor+8..cursor+9])
              invalid_data("@#{cursor} - Invalid ID3v2 frame flags: #{frame_flags}.") if ((frame_flags & 0b00011111_00011111) != 0)
              cursor += 10
              id3v2_metadata[frame_id] = @data[cursor..cursor+((frame_size > MAX_ID3V2_FRAME_SIZE) ? MAX_ID3V2_FRAME_SIZE : frame_size)-1]
              cursor += frame_size
            end
            metadata( :id3v2_metadata => id3v2_metadata )
            # Get directly to the previously computed cursor to skip padding
            log_debug("@#{cursor} - Padding size (#{padding_size}) is different from what is being read (#{cursor_end-cursor}).") if (padding_size != cursor_end-cursor)
            cursor = cursor_end
          elsif (@data[cursor..cursor+7] == BEGIN_PATTERN_APEV2)
            log_debug "=== @#{cursor} - Found APEv2 tag"
            info = decode_ape_tag_header(cursor)
            invalid_data("@#{cursor} - APE tag header indicates no header whereas we have one.") if (!info[:has_header])
            invalid_data("@#{cursor} - APE tag header indicates it is a footer whereas we are on the header.") if (info[:on_footer])
            cursor += 32
            cursor_end_tag = cursor + info[:tag_size]
            ape_metadata = {}
            info[:nbr_items].times do |idx_item|
              item_key, item_value, cursor = decode_ape_tag_item(cursor)
              ape_metadata[item_key] = item_value
            end
            invalid_data("@#{cursor} - APE tag header is inconsistent. We should be at cursor #{cursor_end_tag-(info[:has_footer] ? 32 : 0)}") if (cursor != cursor_end_tag-(info[:has_footer] ? 32 : 0))
            metadata( :apev2_metadata => ape_metadata )
            if (info[:has_footer])
              # There is a footer
              invalid_data("@#{cursor} - Invalid APE tag footer magic.") if (@data[cursor..cursor+7] != BEGIN_PATTERN_APEV2)
              footer_info = decode_ape_tag_header(cursor)
              invalid_data("@#{cursor} - APEv2 tag footer indicates no footer whereas we have one.") if (!footer_info[:has_footer])
              invalid_data("@#{cursor} - APEv2 tag footer indicates it is a header whereas we are on the footer.") if (!footer_info[:on_footer])
              cursor += 32
            end
          else
            # We might be on a APEv1 tag, or real MP3 data, or at the end of our file.
            # APEv1 tag occurs only after the last MP3 frame, and before any ID3v1 tag.
            # APEv1 tag has no header, but a footer.
            ape_tag_decoded = false
            if (nbr_ms != 0)
              # Might be good to check for APEv1 tag
              cursor_begin = cursor
              begin
                ape_metadata = {}
                nbr_items = 0
                while (@data[cursor..cursor+7] != BEGIN_PATTERN_APEV2)
                  item_key, item_value, cursor = decode_ape_tag_item(cursor)
                  ape_metadata[item_key] = item_value
                  nbr_items += 1
                  log_debug "=== @#{cursor} - Decoded APEv1 tag item: #{item_key.inspect} => #{item_value[0..31].inspect}"
                end
                # Here we are on an APE Tag footer
                footer_info = decode_ape_tag_header(cursor)
                invalid_data("@#{cursor} - APEv1 tag footer indicates no footer whereas we have one.") if (!footer_info[:has_footer])
                invalid_data("@#{cursor} - APEv1 tag footer indicates it is a header whereas we are on the footer.") if (!footer_info[:on_footer])
                invalid_data("@#{cursor} - APEv1 tag footer indicates #{footer_info[:nbr_items]} tag items, whereas we read #{nbr_items}") if (footer_info[:nbr_items] != nbr_items)
                log_debug "=== @#{cursor} - Found APEv1 tag"
                cursor += 32
                ape_tag_decoded = true
                metadata( :apev1_metadata => ape_metadata )
              rescue InvalidDataError, TruncatedDataError, AccessAfterDataError
                # Maybe it is not an APEv1 tag.
                # Scratch it and consider a normal MP3 frame.
                #log_debug("=== @#{cursor_begin} - Failed to decode as APEv1 tag: #{$!}")
                cursor = cursor_begin
                ape_tag_decoded = false
              end
            end
            if (!ape_tag_decoded)
              # Real MP3 data or end of file
              info = nil
              begin
                info = decode_mp3_frame_header(cursor)
              rescue InvalidDataError
                if (nbr_ms >= MIN_ACCEPTABLE_TIME_MS)
                  # Consider the file was finished
                  #log_debug "=== @#{cursor} - Garbage data found. Should be end of file."
                  ending_offset = cursor
                else
                  # Problem
                  raise
                end
              end
              if (ending_offset == nil)
                #log_debug "=== @#{cursor} - Found MP3 data"
                # Go see after
                cursor += info[:size]
                # Consider we have valid data only if we have enough milliseconds
                nbr_ms += info[:nbr_ms]
                if ((!valid) and (nbr_ms >= MIN_ACCEPTABLE_TIME_MS))
                  valid = true
                  found_relevant_data(:mp3)
                end
                metadata( :nbr_ms => nbr_ms )
              end
            end
          end
          if ((nbr_ms >= MIN_ACCEPTABLE_TIME_MS) and
              (cursor == @end_offset))
            ending_offset = cursor
          end
          progress(cursor)
        end

        return ending_offset
      end

      private

      # Decode an MP3 frame header
      #
      # Parameters::
      # * *cursor* (_Fixnum_): The cursor
      # Result::
      # * <em>map<Symbol,Object></em>: Corresponding header info
      def decode_mp3_frame_header(cursor)
        info = {}
        # Check the header's values
        header_bytes = @data[cursor..cursor+3].bytes.to_a
        invalid_data("@#{cursor} - Invalid MP3 header") if ((header_bytes[0] != 255) or
                                                            ((header_bytes[1] & 224) != 224) or
                                                            ((header_bytes[1] & 24) == 16) or
                                                            ((header_bytes[1] & 6) == 0) or
                                                            ((header_bytes[2] & 240) == 240) or
                                                            ((header_bytes[2] & 12) == 12) or
                                                            ((header_bytes[3] & 3) == 2))
        invalid_data("@#{cursor} - Invalid MP3 header: can't compute size of free bitrates") if ((header_bytes[2] & 240) == 0)
        # Read header values to compute the size
        version = nil
        case ((header_bytes[1] & 24) >> 3)
        when 0
          version = 3
        when 2
          version = 2
        when 3
          version = 1
        else
          invalid_data("@#{cursor} - Unknown version in header: #{((header_bytes[1] & 24) >> 3)}")
        end
        layer = 4 - ((header_bytes[1] & 6) >> 1)
        bit_rate = BITRATE_INDEX[((header_bytes[2] & 240) >> 4)-1][(version == 1) ? layer - 1 : ((layer == 1) ? 3 : 4)] * 1000
        sample_rate = SAMPLE_RATE_INDEX[(header_bytes[2] & 12) >> 2][version - 1]
        padding = ((header_bytes[2] & 2) >> 1)
        # Compute the size
        info[:size] = (layer == 1) ? ((12 * bit_rate) / sample_rate + padding) * 4 : (144 * bit_rate) / sample_rate + padding
        info[:nbr_ms] = ((layer == 1) ? 384000 : 1152000) / sample_rate
        #log_debug "=== @#{cursor} - Read MP3 frame: Version=#{version} Layer=#{layer} BitRate=#{bit_rate} SampleRate=#{sample_rate} Padding=#{padding} FrameLength=#{info[:size]} Milliseconds=#{info[:nbr_ms]}"
        return info
      end

      # Decode an APE tag header
      #
      # Parameters::
      # * *cursor* (_Fixnum_): Current cursor
      # Result::
      # * <em>map<Symbol,Object></em>: The APE tag info
      def decode_ape_tag_header(cursor)
        info = {}
        #ape_version = BinData::Uint32le.read(@data[cursor+8..cursor+11])
        info[:tag_size] = BinData::Uint32le.read(@data[cursor+12..cursor+15])
        info[:nbr_items] = BinData::Uint32le.read(@data[cursor+16..cursor+19])
        flags = BinData::Uint32le.read(@data[cursor+20..cursor+23])
        info[:has_header] = ((flags & 0b10000000_00000000_00000000_00000000) != 0)
        info[:has_footer] = ((flags & 0b01000000_00000000_00000000_00000000) == 0)
        info[:on_footer] = ((flags & 0b00100000_00000000_00000000_00000000) == 0)
        invalid_data("@#{cursor} - Invalid APE tag flags: #{flags}") if ((flags & 0b00011111_11111111_11111111_11111000) != 0)
        reserved = BinData::Uint64le.read(@data[cursor+24..cursor+31])
        invalid_data("@#{cursor} - Invalid reserved bytes in APE Tag header: #{reserved} should be 0.") if (reserved != 0)
        return info
      end

      # Decode an APE tag item
      #
      # Parameters::
      # * *cursor* (_Fixnum_): The cursor
      # Result::
      # * _String_: Item key
      # * _String_: Item value
      # * _Fixnum_: New cursor
      def decode_ape_tag_item(cursor)
        value_size = BinData::Uint32le.read(@data[cursor..cursor+3])
        flags = BinData::Uint32le.read(@data[cursor+4..cursor+7])
        invalid_data("@#{cursor} - Invalid APE tag flags: #{flags}") if ((flags & 0b00011111_11111111_11111111_11111000) != 0)
        cursor_terminator = @data.index(APE_ITEM_KEY_TERMINATOR, cursor+8)
        invalid_data("@#{cursor} - Could not find the end of APE tag item key.") if (cursor_terminator == nil)
        invalid_data("@#{cursor} - Empty APE tag item key.") if (cursor_terminator == cursor+8)
        item_key = @data[cursor+8..cursor_terminator-1]
        cursor = cursor_terminator + 1
        item_value = @data[cursor..cursor+value_size-1]
        cursor += value_size
        return item_key, item_value, cursor
      end

    end

  end

end
