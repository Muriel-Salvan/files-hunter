module FilesHunter

  module Decoders

    class ICO < BeginPatternDecoder

      BEGIN_PATTERN_ICO = /\x00\x00[\x01\x02]\x00.....\x00/

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
          invalid_data("@#{cursor} - Invalid image header") if (@data[cursor+3] != "\x00")
          images << [ BinData::Uint32le.read(@data[cursor+12..cursor+15]), BinData::Uint32le.read(@data[cursor+8..cursor+11]) ]
          cursor += 16
        end
        progress(cursor)
        found_relevant_data(extension)
        # Decode each image
        images.each do |image_offset, image_size|
          invalid_data("@#{cursor} - Image offset (#{image_offset}) should be #{cursor}") if (cursor != image_offset)
          cursor += image_size
          progress(cursor)
        end
        ending_offset = cursor

        return ending_offset
      end

    end

  end

end
