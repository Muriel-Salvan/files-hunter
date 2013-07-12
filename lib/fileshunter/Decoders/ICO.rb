module FilesHunter

  module Decoders

    class ICO < BeginPatternDecoder

      BEGIN_PATTERN_ICO = Regexp.new("\x00\x00[\x01\x02]\x00.....\x00", nil, 'n')

      ALLOWED_BPP_VALUES = [ 0, 1, 4, 8, 16, 24, 32 ]

      def get_begin_pattern
        return BEGIN_PATTERN_ICO, { :offset_inc => 3, :max_regexp_size => 10 }
      end

      def decode(offset)
        ending_offset = nil

        extension = ((@data[offset+2] == "\x01") ? :ico : :cur)
        nbr_images = BinData::Uint16le.read(@data[offset+4..offset+5])
        invalid_data("@#{offset} - Number of images is 0") if (nbr_images == 0)
        cursor = offset + 6
        # Read all image headers
        images = []
        nbr_images.times do |idx_image|
          #image_width = @data[cursor].ord
          #image_height = @data[cursor+1].ord
          nbr_colors = @data[cursor+2].ord
          invalid_data("@#{cursor} - Invalid ICONDIRENTRY header") if (@data[cursor+3].ord != 0)
          color_planes = BinData::Uint16le.read(@data[cursor+4..cursor+5])
          invalid_data("@#{cursor} - Invalid color planes") if ((extension == :ico) and (color_planes > 1))
          bpp = BinData::Uint16le.read(@data[cursor+6..cursor+7])
          invalid_data("@#{cursor} - Invalid bpp value") if ((extension == :ico) and (!ALLOWED_BPP_VALUES.include?(bpp)))
          invalid_data("@#{cursor} - Invalid number of colors") if ((extension == :ico) and (bpp >= 8) and (nbr_colors != 0))
          image_size = BinData::Uint32le.read(@data[cursor+8..cursor+11])
          invalid_data("@#{cursor} - Invalid image size") if (image_size == 0)
          image_offset = BinData::Uint32le.read(@data[cursor+12..cursor+15])
          images << [ image_offset, image_size ]
          cursor += 16
        end
        progress(cursor)
        # Make sure images are not overlapping
        next_offset_min = cursor-offset
        images.sort.each do |image_offset, image_size|
          invalid_data("@#{cursor} - Invalid image offset: #{image_offset} could not be before #{next_offset_min} as it belongs to another image") if (image_offset < next_offset_min)
          next_offset_min += image_size
        end
        # OK now we consider we might have a valid file
        log_debug "@#{cursor} - #{extension.to_s} file with #{nbr_images} images."
        found_relevant_data(extension)
        metadata(
          :nbr_images => nbr_images
        )
        cursor = offset + next_offset_min
        progress(cursor)
        ending_offset = cursor
        # # Decode each image
        # images.each do |image_offset, image_size|
        #   invalid_data("@#{cursor} - Image offset (#{image_offset}) should be #{cursor-offset}") if (cursor-offset != image_offset)
        #   cursor += image_size
        #   progress(cursor)
        # end
        # ending_offset = cursor

        return ending_offset
      end

    end

  end

end
