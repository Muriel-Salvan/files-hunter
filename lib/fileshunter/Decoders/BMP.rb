module FilesHunter

  module Decoders

    class BMP < BeginPatternDecoder

      BEGIN_PATTERN_BMP = Regexp.new("BM....\x00\x00\x00\x00", nil, 'n')

      def get_begin_pattern
        return BEGIN_PATTERN_BMP, { :offset_inc => 2, :max_regexp_size => 10 }
      end

      def decode(offset)
        ending_offset = nil

        cursor = offset + 14
        header_size = BinData::Uint32le.read(@data[cursor..cursor+3])
        width = nil
        height = nil
        bpp = nil
        header_version = nil
        bitmap_size = nil
        if (header_size == 12)
          # BMP v2 header
          header_version = 2
          width = BinData::Sint16le.read(@data[cursor+4..cursor+5])
          height = BinData::Sint16le.read(@data[cursor+6..cursor+7])
          nbr_planes = BinData::Uint16le.read(@data[cursor+8..cursor+9])
          invalid_data("@#{cursor} - Number of planes (#{nbr_planes}) should always be 1") if (nbr_planes != 1)
          bpp = BinData::Uint16le.read(@data[cursor+10..cursor+11])
          invalid_data("@#{cursor} - Invalid BPP: #{bpp}") if (![1,4,8,16,24,32].include?(bpp))
          cursor += header_size
          # Color palette
          cursor += 3*(1 << bpp) if (bpp != 24)
        else
          # BMP v3+ header
          header_version = 3
          width = BinData::Uint32le.read(@data[cursor+4..cursor+7])
          height = BinData::Uint32le.read(@data[cursor+8..cursor+11])
          nbr_planes = BinData::Uint16le.read(@data[cursor+12..cursor+13])
          invalid_data("@#{cursor} - Number of planes (#{nbr_planes}) should always be 1") if (nbr_planes != 1)
          bpp = BinData::Uint16le.read(@data[cursor+14..cursor+15])
          invalid_data("@#{cursor} - Invalid BPP: #{bpp}") if (![1,4,8,16,24,32].include?(bpp))
          compression = BinData::Uint32le.read(@data[cursor+16..cursor+19])
          invalid_data("@#{cursor} - Invalid compression method: #{compression}") if (compression > 3)
          invalid_data("@#{cursor} - Invalid compression method: #{compression} for given bpp (#{bpp})") if ((compression != 3) and (bpp == 16))
          bitmap_size = BinData::Uint32le.read(@data[cursor+20..cursor+23])
          invalid_data("@#{cursor} - Empty bitmap size for compression method: #{compression}") if ((bitmap_size == 0) and ((compression == 1) or (compression == 2)))
          #ppm_horizontal = BinData::Uint32le.read(@data[cursor+24..cursor+27])
          #ppm_vertical = BinData::Uint32le.read(@data[cursor+28..cursor+31])
          nbr_colors_used = BinData::Uint32le.read(@data[cursor+32..cursor+35])
          invalid_data("@#{cursor} - Number of colors used specified (#{nbr_colors_used} whereas bpp is >= 16 (#{bpp})") if ((bpp >= 16) and (nbr_colors_used > 0))
          #nbr_colors_important = BinData::Uint32le.read(@data[cursor+36..cursor+39])
          if (header_size == 56)
            # BMP v? header
            header_version = 56
          elsif (header_size == 108)
            # BMP v4 header
            header_version = 4
            cstype = BinData::Uint32le.read(@data[cursor+56..cursor+59])
            invalid_data("@#{cursor} - Invalid cstype: #{cstype}") if (cstype > 2)
          end
          cursor += header_size
          # Color palette
          cursor += 4*(1 << bpp) if (bpp < 16)
          cursor += 12 if (((bpp == 16) or (bpp == 32)) and (compression == 3) and (header_version == 3))
        end
        progress(cursor)
        found_relevant_data(:bmp)
        log_debug "@#{cursor} - Decoding bitmap data: header_version=#{header_version} width=#{width} height=#{height} bpp=#{bpp} compression=#{compression} bitmap_size=#{bitmap_size}"
        if ((compression == 0) or
            (compression == 3))
          # Compute the scanline size
          scanline_size = nil
          case bpp
          when 1, 4, 8
            scanline_size, extra = width.divmod(8/bpp)
            scanline_size += 1 if (extra > 0)
          when 16, 24, 32
            scanline_size = width * (bpp/8)
            scanline_size *= 2 if ((bpp == 16) and (header_version == 4))
          end
          rest = scanline_size % 4
          scanline_size += 4 - rest if (rest > 0)
          computed_bitmap_size = scanline_size * height
          cursor += computed_bitmap_size
        else
          cursor += bitmap_size
        end
        progress(cursor)
        ending_offset = cursor

        return ending_offset
      end

    end

  end

end
