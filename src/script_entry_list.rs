use serde::{Deserialize, Serialize};
use std::{io, io::{Read, Write, Seek, SeekFrom}};
use std::string::{FromUtf8Error, FromUtf16Error};
use std::collections::{HashSet, HashMap};
use pmd_sir0::write_sir0_footer;

#[derive(Debug)]
pub enum ScriptEntryListError {
    IOError(io::Error),
    InvalidHeader([u8; 4]),
    FromUtf8Error(FromUtf8Error),
    FromUtf16Error(FromUtf16Error),
}

impl From<io::Error> for ScriptEntryListError {
    fn from(err: io::Error) -> ScriptEntryListError {
        ScriptEntryListError::IOError(err)
    }
}

impl From<FromUtf8Error> for ScriptEntryListError {
    fn from(err: FromUtf8Error) -> ScriptEntryListError {
        ScriptEntryListError::FromUtf8Error(err)
    }
}

impl From<FromUtf16Error> for ScriptEntryListError {
    fn from(err: FromUtf16Error) -> ScriptEntryListError {
        ScriptEntryListError::FromUtf16Error(err)
    }
}

pub fn read_u32<F: Read>(file: &mut F) -> Result<u32, ScriptEntryListError> {
    let mut buffer = [0; 4];
    file.read_exact(&mut buffer)?;
    Ok(u32::from_le_bytes(buffer))
}

pub fn read_referenced_utf8_string<F: Read + Seek>(file: &mut F, reference: u64) -> Result<String, ScriptEntryListError> {
    file.seek(SeekFrom::Start(reference))?;
    let mut result = String::new();
    let mut buffer = [0];
    loop {
        file.read_exact(&mut buffer)?;
        if buffer == [0] {
            return Ok(result)
        };
        result.push_str(&String::from_utf8(buffer.to_vec())?)
    }
}

pub fn read_referenced_utf16_string<F: Read + Seek>(file: &mut F, reference: u64) -> Result<String, ScriptEntryListError> {
    file.seek(SeekFrom::Start(reference))?;
    let mut result = String::new();
    let mut buffer = [0; 2];
    loop {
        file.read_exact(&mut buffer)?;
        let charid = u16::from_le_bytes(buffer);
        if charid == 0 {
            return Ok(result)
        };
        result.push_str(&String::from_utf16(&[charid])?)
    }
}

pub fn string_to_utf16(string: &str) -> Vec<u8> {
    let mut result = Vec::new();
    for chara in string.encode_utf16() {
        result.extend_from_slice(&u16::to_le_bytes(chara))
    };
    result
}

#[derive(Serialize, Deserialize)]
pub struct ScriptEntry {
    pub entity_name: String,
    pub map_name: String,
    pub lua_path: String,
    pub plb_path: String,
    pub flags: [u32; 4],
}

#[derive(Serialize, Deserialize)]
pub struct ScriptEntryList {
    pub entries: Vec<ScriptEntry>,
}

impl ScriptEntryList {
    pub fn new_from_file<F: Read + Seek>(file: &mut F) -> Result<ScriptEntryList, ScriptEntryListError> {
        file.seek(SeekFrom::Start(0))?;
        let mut header_buf = [0; 4];
        file.read_exact(&mut header_buf)?;
        if &header_buf != b"SIR0" {
            return Err(ScriptEntryListError::InvalidHeader(header_buf));
        };

        let pointer_content_data = read_u32(file)?;
        let _pointer_pointer_offsets = read_u32(file)?;

        file.seek(SeekFrom::Start(pointer_content_data as u64))?;
        let entry_count = read_u32(file)?;
        let pointer_entry_list = read_u32(file)?;

        file.seek(SeekFrom::Start(pointer_entry_list as u64))?;
        let mut all_pointer_entry = Vec::new();
        for _ in 0..entry_count {
            all_pointer_entry.push(read_u32(file)? as u64);
        };

        let mut entries = Vec::new();
        for pointer_entry in all_pointer_entry {
            file.seek(SeekFrom::Start(pointer_entry))?;

            let actual_entity_name_pointer = read_u32(file)? as u64;
            let actual_map_name_pointer = read_u32(file)? as u64;
            let actual_lua_path_pointer = read_u32(file)? as u64;
            let actual_plb_path_pointer = read_u32(file)? as u64;
            let actual_flags_pointer = read_u32(file)? as u64;

            let entity_name = read_referenced_utf8_string(file, actual_entity_name_pointer)?;
            let map_name = read_referenced_utf8_string(file, actual_map_name_pointer)?;
            let lua_path = read_referenced_utf16_string(file, actual_lua_path_pointer)?;
            let plb_path = read_referenced_utf16_string(file, actual_plb_path_pointer)?;

            file.seek(SeekFrom::Start(actual_flags_pointer))?;
            let mut flags = [0; 4];
            #[allow(clippy::needless_range_loop)]
            for flag_id in 0..4 {
                flags[flag_id] = read_u32(file)?;
            };

            entries.push(ScriptEntry {
                entity_name,
                map_name,
                lua_path,
                plb_path,
                flags,
            });
        };

        Ok(ScriptEntryList {
            entries
        })
    }

    pub fn write_to_file<F: Write + Seek>(&self, file: &mut F) -> Result<(), ScriptEntryListError> {
        let mut sir0_pointers = Vec::new();
        file.write_all(b"SIR0")?;

        // pointer content data
        sir0_pointers.push(file.seek(SeekFrom::Current(0))? as u32);
        file.write_all(&u32::to_le_bytes(16))?;

        // pointer specific to sir0
        sir0_pointers.push(file.seek(SeekFrom::Current(0))? as u32);
        file.write_all(&[0; 4])?; //TODO:

        // magic
        file.write_all(&[0; 4])?;

        // content data header
        // entry_count
        file.write_all(&u32::to_le_bytes(self.entries.len() as u32))?;

        // pointer to list of pointer to entry
        sir0_pointers.push(file.seek(SeekFrom::Current(0))? as u32);
        file.write_all(&u32::to_le_bytes(24))?;


        // list of pointer to entry -- will be overwritten
        //TODO:
        //let mut list_pointer_to_entry = Vec::new();
        for _ in 0..self.entries.len() {
            sir0_pointers.push(file.seek(SeekFrom::Current(0))? as u32);
            file.write_all(&[0; 4])?;
        };

        // list of entries -- will be overwritten
        let list_of_entries_pointer = file.seek(SeekFrom::Current(0))?;
        for _ in 0..self.entries.len() {
            sir0_pointers.push(file.seek(SeekFrom::Current(0))? as u32);
            file.write_all(&[0; 4])?;
            sir0_pointers.push(file.seek(SeekFrom::Current(0))? as u32);
            file.write_all(&[0; 4])?;
            sir0_pointers.push(file.seek(SeekFrom::Current(0))? as u32);
            file.write_all(&[0; 4])?;
            sir0_pointers.push(file.seek(SeekFrom::Current(0))? as u32);
            file.write_all(&[0; 4])?;
            sir0_pointers.push(file.seek(SeekFrom::Current(0))? as u32);
            file.write_all(&[0; 4])?;
        }

        // list of flags
        // the original compiler doesn't seem to try to elimate double entry
        let mut flags_pointer = Vec::new();
        for entry in &self.entries {
            flags_pointer.push(file.seek(SeekFrom::Current(0))?);
            for flag_id in 0..4 {
                file.write_all(&u32::to_le_bytes(entry.flags[flag_id]))?;
            }
        }

        // strings
        let mut utf16_string_to_write_set = HashSet::new();
        let mut utf8_string_to_write_set = HashSet::new();
        for entry in &self.entries {
            utf16_string_to_write_set.insert(entry.lua_path.clone());
            utf16_string_to_write_set.insert(entry.plb_path.clone());
            utf8_string_to_write_set.insert(entry.entity_name.clone());
            utf8_string_to_write_set.insert(entry.map_name.clone());
        }

        let mut utf16_string_map = HashMap::new();
        for string in utf16_string_to_write_set {
            let string_start_offset = file.seek(SeekFrom::Current(0))?;
            file.write_all(&string_to_utf16(&string))?;
            file.write_all(&[0; 2])?;
            utf16_string_map.insert(string, string_start_offset);
        };


        let mut utf8_string_map = HashMap::new();
        for string in utf8_string_to_write_set {
            let string_start_offset = file.seek(SeekFrom::Current(0))?;
            file.write_all(string.as_bytes())?;
            file.write_all(&[0])?;
            utf8_string_map.insert(string, string_start_offset);
        };

        let sir0_list_pointer = file.seek(SeekFrom::Current(0))?;

        // write list of entries
        file.seek(SeekFrom::Start(list_of_entries_pointer))?;
        let mut entries_pointer = Vec::new();
        for (entryid, entry) in self.entries.iter().enumerate() {
            entries_pointer.push(file.seek(SeekFrom::Current(0))?);
            file.write_all(&u32::to_le_bytes(utf8_string_map[&entry.entity_name] as u32))?;
            file.write_all(&u32::to_le_bytes(utf8_string_map[&entry.map_name] as u32))?;
            file.write_all(&u32::to_le_bytes(utf16_string_map[&entry.lua_path] as u32))?;
            file.write_all(&u32::to_le_bytes(utf16_string_map[&entry.plb_path] as u32))?;
            file.write_all(&u32::to_le_bytes(flags_pointer[entryid] as u32))?;
        }

        // write list of pointer to entries
        file.seek(SeekFrom::Start(24))?;
        for pointer in entries_pointer {
            file.write_all(&u32::to_le_bytes(pointer as u32))?;
        };



        // write sir0 end
        file.seek(SeekFrom::Start(sir0_list_pointer))?;

        // write a padding
        while file.seek(SeekFrom::Current(0))?%4 != 0 {
            file.write_all(&[0])?;
        };

        let sir0_list_padded = file.seek(SeekFrom::Current(0))?;

        // write the sir0 pointer list
        write_sir0_footer(file, sir0_pointers)?;


        file.seek(SeekFrom::Start(8))?;
        file.write_all(&u32::to_le_bytes(sir0_list_padded as u32))?;
        Ok(())
    }
}
