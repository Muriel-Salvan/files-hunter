module FilesHunter

  module Decoders

    class CFBF < BeginPatternDecoder

      BEGIN_PATTERN_CFBF = "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".force_encoding('ASCII-8BIT')

      KNOWN_EXTENSIONS = {
        'MSWordDoc' => :doc,
        "P\x00o\x00w\x00e\x00r\x00P\x00o\x00i\x00n\x00t\x00" => :pps,
        'Microsoft Excel' => :xls,
        "C\x00a\x00t\x00a\x00l\x00o\x00g\x00" => :db
      }

      def get_begin_pattern
        return BEGIN_PATTERN_CFBF, { :offset_inc => 24 }
      end

      def decode(offset)
        # Know if we are little or big-endian
        big_endian = (@data[offset+28..offset+29] == "\xFF\xFE")
        bindata32 = big_endian ? BinData::Uint32be : BinData::Uint32le
        bindata16 = big_endian ? BinData::Uint16be : BinData::Uint16le
        # Read sector size
        vector_size = 1 << bindata16.read(@data[offset+30..offset+31])

        # Count the number of sectors
        # Read the MSAT (first 109 entries)
        msat = @data[offset+76..offset+511]
        found_relevant_data(:doc) # Default
        first_sector_offset = offset + 512
        # Check if there are additional MSAT sectors
        next_msat_sector_id = bindata32.read(@data[offset+68..offset+71])
        while (next_msat_sector_id < 4294967292)
          # Read the MSAT
          msat.concat(@data[first_sector_offset+next_msat_sector_id*vector_size..first_sector_offset+(next_msat_sector_id+1)*vector_size-5])
          # The last sector ID is the next MSAT sector one
          next_msat_sector_id = bindata32.read(@data[first_sector_offset+(next_msat_sector_id+1)*vector_size-4..first_sector_offset+(next_msat_sector_id+1)*vector_size-1])
        end
        # Decode the MSAT and read each SAT sector
        sat_sector_ids = []
        log_debug "=== Size of MSAT: #{msat.size}"
        (msat.size / 4).times do |idx|
          sector_id = bindata32.read(msat[idx*4..idx*4+3])
          sat_sector_ids << sector_id if (sector_id < 4294967292)
        end
        # Read each SAT sector and get the maximum sector ID
        max_sector_id = -1
        sat_sector_ids.each do |container_sector_id|
          sector_offset = first_sector_offset + container_sector_id*vector_size
          (vector_size / 4).times do |idx|
            sector_id = bindata32.read(@data[sector_offset+idx*4..sector_offset+idx*4+3])
            if ((sector_id < 4294967292) and
                (sector_id > max_sector_id))
              max_sector_id = sector_id
            end
          end
        end
        # We got the number of sectors
        nbr_sectors = max_sector_id + 1
        log_debug "=== Number of sectors: #{nbr_sectors}"
        metadata(
          :msat_size => msat.size,
          :nbr_sectors => nbr_sectors
        )

        # Now find some info about the file extension
        found_extension = false
        nbr_sectors.times do |idx_sector|
          log_debug "=== Find extension @ sector #{idx_sector}"
          KNOWN_EXTENSIONS.each do |token, extension|
            if (@data[first_sector_offset+idx_sector*vector_size..first_sector_offset+(idx_sector+1)*vector_size-1].index(token) != nil)
              log_debug "=== Found extension #{extension}"
              found_relevant_data(extension)
              found_extension = true
              break
            end
          end
          break if found_extension
        end
        log_debug "@#{offset} - Unable to get extension from CFBF document." if (!found_extension)

        return first_sector_offset + nbr_sectors*vector_size
      end

    end

  end

end
