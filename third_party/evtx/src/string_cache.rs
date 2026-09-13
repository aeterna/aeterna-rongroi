use crate::ChunkOffset;
use crate::binxml::name::{BinXmlName, BinXmlNameLink};
use crate::err::DeserializationResult;
use crate::utils::ByteCursor;

use ahash::AHashMap;
use log::trace;

#[derive(Debug)]
pub(crate) struct StringCache(AHashMap<ChunkOffset, BinXmlName>);

impl StringCache {
    pub(crate) fn populate(data: &[u8], offsets: &[ChunkOffset]) -> DeserializationResult<Self> {
        let mut cache = AHashMap::new();

        for &offset in offsets.iter().filter(|&&offset| offset > 0) {
            let mut cursor = ByteCursor::with_pos(data, offset as usize)?;

            loop {
                let string_position = cursor.pos() as ChunkOffset;
                let link = BinXmlNameLink::from_cursor(&mut cursor)?;
                let name = BinXmlName::from_cursor(&mut cursor)?;

                // A non-empty return from `insert` means this position has already been walked —
                // earlier in this chain, or in an earlier one — and everything reachable from it was
                // cached then, so stopping here loses no string while walking on would follow the
                // same links again and never come back. Only a chain entry pointing at *itself* was
                // caught below; a cycle of two or more was walked forever, and because the same keys
                // are overwritten each time round, memory does not grow and nothing reports it. The
                // `offset == string_position` check below is the one-element case of this and is
                // left as upstream wrote it. What is *accepted* does not change: a chain that ends
                // is walked to its end exactly as before, and a chunk is not refused for holding a
                // cycle — the strings in it are cached and its records still resolve them.
                if cache.insert(string_position, name).is_some() {
                    break;
                }

                trace!("\tNext string will be at {:?}", link.next_string);

                match link.next_string {
                    Some(offset) => {
                        if offset == string_position {
                            break;
                        }
                        cursor.set_pos(offset as usize, "next xml string")?;
                    }
                    None => break,
                }
            }
        }

        Ok(StringCache(cache))
    }

    pub(crate) fn get_cached_string(&self, offset: ChunkOffset) -> Option<&BinXmlName> {
        self.0.get(&offset)
    }
}
