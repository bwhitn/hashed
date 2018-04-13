event bro_init()
	{
        #Files::ANALYZER_DATA_EVENT
	}

event file_state_remove(f: fa_file)
	{

	}

event file_gap(f: fa_file, offset: count, len: count)
	{

	}

event file_timeout(f: fa_file)
	{

	}

event file_new(f: fa_file)
	{

	}

event file_stream(f: fa_file, data: string)
	{

	}

event file_chunk(f: fa_file, data: string, off: count)
	{

	}

	fa_file seen_bytes: