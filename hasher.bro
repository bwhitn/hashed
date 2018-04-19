module hasher;

const num_of_hashes = 20;
const max_file_size = 4194304;
const min_file_size = 300;
const min_hash_bytes = 8;
const e_85_divisor = vector(52200625, 614125, 7225, 85, 1);
const e_85_char = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-_?+=^!/*&<>()[]{}@%$~";

event bro_init()
	{

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

event file_stream(f: fa_file, data: string)
	{
	print f;
	}

event file_new(f: fa_file)
	{
	Files::add_analyzer(f, Files::ANALYZER_DATA_EVENT, [$stream_event=file_stream]);
	}



#event file_chunk(f: fa_file, data: string, off: count)
#	{
#
#	}

#fa_file missing_bytes:uint, timedout:bool