module FilesHunter

  module Decoders

    class TIFF < BeginPatternDecoder

      # TIFF Reference: http://partners.adobe.com/public/developer/en/tiff/TIFF6.pdf
      # Exif Reference: http://www.exif.org/Exif2-2.PDF

      BEGIN_PATTERN_TIFF_LE = "II*\x00".force_encoding(Encoding::ASCII_8BIT)
      BEGIN_PATTERN_TIFF_BE = "MM\x00*".force_encoding(Encoding::ASCII_8BIT)
      BEGIN_PATTERN_TIFF = Regexp.new("(#{Regexp.escape(BEGIN_PATTERN_TIFF_LE)}|#{Regexp.escape(BEGIN_PATTERN_TIFF_BE)})", nil, 'n')

      TYPE_SIZES = {
        1 => 1,
        2 => 1,
        3 => 2,
        4 => 4,
        5 => 8,
        6 => 1,
        7 => 1,
        8 => 2,
        9 => 4,
        10 => 8,
        11 => 4,
        12 => 8
      }

      VALID_COMPRESSION_VALUES = [ 1, 2, 3, 4, 5, 6, 32773 ]
      VALID_PHOTOMETRIC_INTERPRETATIONS = [ 0, 1, 2, 3, 4, 5, 6, 8 ]

      TRAILING_00_REGEXP = Regexp.new("\x00*$".force_encoding(Encoding::ASCII_8BIT), nil, 'n')
      NULL_TERMINATING_CHAR = "\x00".force_encoding(Encoding::ASCII_8BIT)

      def initialize
        super
        @accept_no_image_data = false
      end

      def get_begin_pattern
        return BEGIN_PATTERN_TIFF, { :offset_inc => 4, :max_regexp_size => 4 }
      end

      # Set this decoder to accept no image data.
      # This is particularly useful for other decoders using it (for example with JPEG and its Exif info)
      def accept_no_image_data
        @accept_no_image_data = true
      end

      def decode(offset)
        @file_offset = offset
        @bindata_reader_16 = nil
        @bindata_reader_32 = nil
        if (@data[offset..offset+3] == BEGIN_PATTERN_TIFF_LE)
          @bindata_reader_16 = BinData::Uint16le
          @bindata_reader_32 = BinData::Uint32le
        else
          @bindata_reader_16 = BinData::Uint16be
          @bindata_reader_32 = BinData::Uint32be
        end
        ifd_offset = @bindata_reader_32.read(@data[offset+4..offset+7])
        extensions = [:tif, :tiff] # By default
        @max_end_offset = ifd_offset
        @strip_offsets = []
        @strip_byte_counts = []
        @tile_offsets = []
        @tile_byte_counts = []
        @compression = 1
        @lst_bits_per_sample = [1]
        @image_width = nil
        @image_length = nil
        @tag_parser = Proc.new do |tag, type, nbr, size, cursor|
          case tag.to_i
          when 2
            metadata( :gps_latitude => @data[cursor..cursor+size-1] )
          when 4
            metadata( :gps_longitude => @data[cursor..cursor+size-1] )
          when 6
            metadata( :gps_altitude => @data[cursor..cursor+size-1] )
          when 7
            metadata( :gps_timestamp => [
              read_ratio(cursor),
              read_ratio(cursor+8),
              read_ratio(cursor+16),
            ] )
          when 256
            @image_width = ((type == 3) ? @bindata_reader_16.read(@data[cursor..cursor+1]) : @bindata_reader_32.read(@data[cursor..cursor+3]))
            invalid_data("@#{cursor} - Invalid image width #{@image_width}") if (@image_width == 0)
            metadata( :image_width => @image_width )
          when 257
            @image_length = ((type == 3) ? @bindata_reader_16.read(@data[cursor..cursor+1]) : @bindata_reader_32.read(@data[cursor..cursor+3]))
            invalid_data("@#{cursor} - Invalid image length #{@image_length}") if (@image_length == 0)
            metadata( :image_length => @image_length )
          when 258
            @lst_bits_per_sample = []
            nbr.times do |idx_sample|
              @lst_bits_per_sample << @bindata_reader_16.read(@data[cursor+2*idx_sample..cursor+2*idx_sample+1])
            end
            metadata( :lst_bits_per_sample => @lst_bits_per_sample )
          when 259
            @compression = @bindata_reader_16.read(@data[cursor..cursor+1])
            invalid_data("@#{cursor} - Invalid compression #{@compression}") if (!VALID_COMPRESSION_VALUES.include?(@compression))
            metadata( :compression => @compression )
          when 262
            photometric_interpretation = @bindata_reader_16.read(@data[cursor..cursor+1])
            invalid_data("@#{cursor} - Invalid photometric interpretation #{photometric_interpretation}") if (!VALID_PHOTOMETRIC_INTERPRETATIONS.include?(photometric_interpretation))
            metadata( :photometric_interpretation => photometric_interpretation )
          when 264
            cell_width = @bindata_reader_16.read(@data[cursor..cursor+1])
            invalid_data("@#{cursor} - Invalid cell width #{cell_width}") if (cell_width == 0)
            metadata( :cell_width => cell_width )
          when 265
            cell_length = @bindata_reader_16.read(@data[cursor..cursor+1])
            invalid_data("@#{cursor} - Invalid cell length #{cell_length}") if (cell_length == 0)
            metadata( :cell_length => cell_length )
          when 266
            fill_order = @bindata_reader_16.read(@data[cursor..cursor+1])
            invalid_data("@#{cursor} - Invalid fill order #{fill_order}") if ((fill_order == 0) or (fill_order > 2))
            metadata( :fill_order => fill_order )
          when 269
            metadata( :document_name => read_ascii(cursor, size) )
          when 270
            metadata( :image_description => read_ascii(cursor, size) )
          when 271
            metadata( :make => read_ascii(cursor, size) )
          when 272
            metadata( :model => read_ascii(cursor, size) )
          when 273
            value_size = ((type == 3) ? 2 : 4)
            nbr.times do |idx|
              @strip_offsets << ((type == 3) ? @bindata_reader_16.read(@data[cursor+idx*value_size..cursor+idx*value_size+1]) : @bindata_reader_32.read(@data[cursor+idx*value_size..cursor+idx*value_size+3]))
            end
            found_relevant_data(extensions)
          when 274
            orientation = @bindata_reader_16.read(@data[cursor..cursor+1])
            invalid_data("@#{cursor} - Invalid orientation #{orientation}") if ((orientation == 0) or (orientation > 8))
            metadata( :orientation => orientation )
          when 277
            samples_per_pixel = @bindata_reader_16.read(@data[cursor..cursor+1])
            invalid_data("@#{cursor} - Invalid samples per pixel #{samples_per_pixel}") if (samples_per_pixel == 0)
            metadata( :samples_per_pixel => samples_per_pixel )
          when 278
            rows_per_strip = ((type == 3) ? @bindata_reader_16.read(@data[cursor..cursor+1]) : @bindata_reader_32.read(@data[cursor..cursor+3]))
            invalid_data("@#{cursor} - Invalid rows per strip #{rows_per_strip}") if (rows_per_strip == 0)
            metadata( :rows_per_strip => rows_per_strip )
          when 279
            value_size = ((type == 3) ? 2 : 4)
            nbr.times do |idx|
              @strip_byte_counts << ((type == 3) ? @bindata_reader_16.read(@data[cursor+idx*value_size..cursor+idx*value_size+1]) : @bindata_reader_32.read(@data[cursor+idx*value_size..cursor+idx*value_size+3]))
            end
          when 282
            ratio = read_ratio(cursor)
            invalid_data("@#{cursor} - Invalid x resolution #{ratio}") if (ratio == 0)
            metadata( :x_resolution => ratio )
          when 283
            ratio = read_ratio(cursor)
            invalid_data("@#{cursor} - Invalid y resolution #{ratio}") if (ratio == 0)
            metadata( :y_resolution => ratio )
          when 285
            metadata( :page_name => read_ascii(cursor, size) )
          when 296
            resolution_unit = @bindata_reader_16.read(@data[cursor..cursor+1])
            invalid_data("@#{cursor} - Invalid resolution unit #{resolution_unit}") if ((resolution_unit == 0) or (resolution_unit > 3))
            metadata( :resolution_unit => resolution_unit )
          when 297
            page_number = @bindata_reader_16.read(@data[cursor..cursor+1])
            page_total = @bindata_reader_16.read(@data[cursor+2..cursor+3])
            invalid_data("@#{cursor} - Invalid page total #{page_total}") if (page_total == 0)
            metadata( :page_number => page_number, :page_total => page_total )
          when 305
            metadata( :software => read_ascii(cursor, size) )
          when 306
            metadata( :date_time => read_ascii(cursor, size) )
          when 315
            metadata( :artist => read_ascii(cursor, size) )
          when 316
            metadata( :host_computer => read_ascii(cursor, size) )
          when 324
            nbr.times do |idx|
              @tile_offsets << @bindata_reader_32.read(@data[cursor+idx*4..cursor+idx*4+3])
            end
            found_relevant_data(extensions)
          when 325
            nbr.times do |idx|
              @tile_byte_counts << @bindata_reader_32.read(@data[cursor+idx*4..cursor+idx*4+3])
            end
          when 337
            metadata( :target_printer => read_ascii(cursor, size) )
          when 33432
            metadata( :copyright => read_ascii(cursor, size) )
          when 33434
            metadata( :exposure_time => read_ratio(cursor) )
          when 33437
            metadata( :f_number => read_ratio(cursor) )
          when 34665
            exif_ifd_offset = @bindata_reader_32.read(@data[cursor..cursor+3])
            metadata( :exif_ifd => true )
            parse_ifd(exif_ifd_offset, &@tag_parser)
          when 34853
            gps_ifd_offset = @bindata_reader_32.read(@data[cursor..cursor+3])
            metadata( :gps_ifd => true )
            parse_ifd(gps_ifd_offset, &@tag_parser)
          when 36864
            metadata( :exif_version => read_ascii(cursor, size) )
          when 36867
            metadata( :date_time_original => read_ascii(cursor, size) )
          when 36868
            metadata( :date_time_digitized => read_ascii(cursor, size) )
          when 37386
            metadata( :focal_length => read_ratio(cursor) )
          when 37510
            metadata( :user_comment => read_ascii(cursor, size) )
          when 37520
            metadata( :subsec_time => read_ascii(cursor, size) )
          when 37521
            metadata( :subsec_time_original => read_ascii(cursor, size) )
          when 37522
            metadata( :subsec_time_digitized => read_ascii(cursor, size) )
          when 40960
            metadata( :flashpix_version => read_ascii(cursor, size) )
          when 40962
            metadata( :pixel_x_dimension => ((type == 3) ? @bindata_reader_16.read(@data[cursor..cursor+1]) : @bindata_reader_32.read(@data[cursor..cursor+3])) )
          when 40963
            metadata( :pixel_y_dimension => ((type == 3) ? @bindata_reader_16.read(@data[cursor..cursor+1]) : @bindata_reader_32.read(@data[cursor..cursor+3])) )
          when 40965
            interoperability_ifd_offset = @bindata_reader_32.read(@data[cursor..cursor+3])
            metadata( :interoperability_ifd => true )
            parse_ifd(interoperability_ifd_offset, &@tag_parser)
          end
        end
        parse_ifd(ifd_offset, &@tag_parser)
        log_debug "@#{@file_offset + @max_end_offset} - Found #{@strip_offsets.size} strips and #{@tile_offsets.size} tiles."
        found_relevant_data(extensions)
        invalid_data("@#{@file_offset + @max_end_offset} - No strips nor tiles defined.") if ((!@accept_no_image_data) and (@strip_offsets.empty?) and (@tile_offsets.empty?))
        # Special case:
        if ((@strip_offsets.size == 1) and
            (@strip_byte_counts.empty?))
          # Compute the strip size: this is the total image size
          invalid_data("@#{@file_offset + @max_end_offset} - Missing strip byte counts and image is compressed") if (@compression != 1)
          invalid_data("@#{@file_offset + @max_end_offset} - Missing image width") if (@image_width == nil)
          invalid_data("@#{@file_offset + @max_end_offset} - Missing image length") if (@image_length == nil)
          # Compute a single row size
          nbr_bits_per_pixel = 0
          all_samples_16 = true
          all_samples_32 = true
          @lst_bits_per_sample.each do |nbr_bits|
            nbr_bits_per_pixel += nbr_bits
            all_samples_16 = false if (nbr_bits != 16)
            all_samples_32 = false if (nbr_bits != 32)
          end
          row_size_bits = @image_width * nbr_bits_per_pixel
          # Compute the padding in bits
          bits_padding = (all_samples_16 ? 16 : (all_samples_32 ? 32 : 8))
          bits_rest = row_size_bits % bits_padding
          row_size_bits += bits_padding - bits_rest if (bits_rest != 0)
          # We have the real row size
          image_end_offset = @strip_offsets[0] + @image_length * (row_size_bits / 8)
          @max_end_offset = image_end_offset if (@max_end_offset < image_end_offset)
        else
          invalid_data("@#{@file_offset + @max_end_offset} - Found #{@strip_offsets.size} strip offsets but #{@strip_byte_counts.size} strip bytes count") if (@strip_offsets.size != @strip_byte_counts.size)
          invalid_data("@#{@file_offset + @max_end_offset} - Found #{@tile_offsets.size} tile offsets but #{@tile_byte_counts.size} tile bytes count") if (@tile_offsets.size != @tile_byte_counts.size)
          # Read all strips
          @strip_offsets.each_with_index do |strip_offset, idx_strip|
             @max_end_offset = strip_offset + @strip_byte_counts[idx_strip] if (@max_end_offset < strip_offset + @strip_byte_counts[idx_strip])
          end
          # Read all tiles
          @tile_offsets.each_with_index do |tile_offset, idx_tile|
             @max_end_offset = tile_offset + @tile_byte_counts[idx_tile] if (@max_end_offset < tile_offset + @tile_byte_counts[idx_tile])
          end
        end

        return @file_offset + @max_end_offset
      end

      private

      # Parse an IFD
      #
      # Parameters::
      # * *ifd_offset* (_Fixnum_): IFD offset to parse
      # * *&proc* (_Proc_): Code called each time a tag is being parsed:
      #   * Parameters::
      #   * *tag* (_Fixnum_): Tag read
      #   * *type* (_Fixnum_): Type of this tag
      #   * *nbr* (_Fixnum_): Number of values in this tag
      #   * *size* (_Fixnum_): Complete size of this tag
      #   * *cursor* (_Fixnum_): Cursor to read the values from
      def parse_ifd(ifd_offset, &proc)
        log_debug "@#{@file_offset + ifd_offset} - Parse IFD"
        while (ifd_offset != 0)
          cursor = @file_offset + ifd_offset
          nbr_entries = @bindata_reader_16.read(@data[cursor..cursor+1])
          cursor += 2
          nbr_entries.times do |idx_entry|
            tag = @bindata_reader_16.read(@data[cursor..cursor+1])
            type = @bindata_reader_16.read(@data[cursor+2..cursor+3])
            nbr = @bindata_reader_32.read(@data[cursor+4..cursor+7])
            # Compute the size
            invalid_data("@#{cursor} - Invalid type: #{type}") if (!TYPE_SIZES.include?(type))
            size = TYPE_SIZES[type]*nbr
            # Read the offset of the value
            value_offset = @bindata_reader_32.read(@data[cursor+8..cursor+11])
            log_debug "@#{cursor} - Found tag #{tag} (type #{type}) with #{nbr} values (size #{size}): #{value_offset}"
            if (size > 4)
              yield(tag, type, nbr, size, @file_offset + value_offset)
              value_end_offset = value_offset + size
              @max_end_offset = value_end_offset if (@max_end_offset < value_end_offset)
            else
              yield(tag, type, nbr, size, cursor + 8)
            end
            cursor += 12
            progress(cursor)
          end
          ifd_end_offset = ifd_offset + 6 + nbr_entries*12
          @max_end_offset = ifd_end_offset if (@max_end_offset < ifd_end_offset)
          # Read the next ifd offset
          ifd_offset = @bindata_reader_32.read(@data[cursor..cursor+3])
        end
      end

      # Read an ASCII value
      #
      # Parameters::
      # * *cursor* (_Fixnum_): The cursor to read from
      # * *size* (_Fixnum_): Size of the string
      # Result::
      # * _String_ or <em>list<String></em>: Resulting string or list of strings if several.
      def read_ascii(cursor, size)
        lst_strings = @data[cursor..cursor+size-1].gsub(TRAILING_00_REGEXP, '').strip.split(NULL_TERMINATING_CHAR)
        return (lst_strings.size == 1) ? lst_strings[0] : lst_strings
      end

      # Read a Rational value
      #
      # Parameters::
      # * *cursor* (_Fixnum_): The cursor to read from
      # Result::
      # * _Float_: The rational
      def read_ratio(cursor)
        num = @bindata_reader_32.read(@data[cursor..cursor+3])
        denom = @bindata_reader_32.read(@data[cursor+4..cursor+7])
        invalid_data("@#{cursor} - Invalid rational #{num}/#{denom}") if ((denom == 0) and (num != 0))
        return (num == 0) ? 0 : num.to_f / denom.to_f
      end

    end

  end

end
