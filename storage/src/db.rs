use crate::crdt::CrdtRecord;
use rusqlite::{params, Connection, Result};

/// Koknet's Zero-Metadata and Local-First Storage Engine.
/// Operates entirely on the edge device, removing reliance on centralized cloud databases.
pub struct KoknetDb {
    conn: Connection,
}

impl KoknetDb {
    /// Initializes the local SQLite database.
    pub fn new(db_path: &str) -> Result<Self> {
        let conn = Connection::open(db_path)?;
        let db = Self { conn };
        db.init_schema()?;
        Ok(db)
    }

    /// Sets up the required schema for storing CRDT records persistently on the device.
    fn init_schema(&self) -> Result<()> {
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS crdt_store (
                id TEXT PRIMARY KEY,
                author_id TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                payload BLOB NOT NULL,
                signature BLOB NOT NULL
            )",
            [],
        )?;
        Ok(())
    }

    /// CRDT Merge Logic (Conflict-free Resolution):
    /// Attempts to insert or update a record in the local database.
    /// If the ID already exists, it compares timestamps. If the incoming record's timestamp
    /// is newer (greater), it overwrites the local data (LWW paradigm).
    /// If older, the incoming data is ignored. This process operates autonomously without central coordination.
    pub fn merge_crdt_record(&self, record: &CrdtRecord) -> Result<bool> {
        // Retrieve the current timestamp of the associated record, if it exists
        let current_ts: Result<i64> = self.conn.query_row(
            "SELECT timestamp FROM crdt_store WHERE id = ?1",
            params![record.id],
            |row| row.get(0),
        );

        match current_ts {
            Ok(ts) if ts >= record.timestamp => {
                // Local record is newer or equal. Do not update. (Conflict resolved)
                Ok(false)
            }
            _ => {
                // Record either does not exist locally (Err), or the incoming record is newer.
                // Perform an 'Upsert' operation.
                self.conn.execute(
                    "INSERT INTO crdt_store (id, author_id, timestamp, payload, signature) 
                     VALUES (?1, ?2, ?3, ?4, ?5)
                     ON CONFLICT(id) DO UPDATE SET 
                        author_id=excluded.author_id,
                        timestamp=excluded.timestamp,
                        payload=excluded.payload,
                        signature=excluded.signature",
                    params![
                        record.id,
                        record.author_id,
                        record.timestamp,
                        record.payload,
                        record.signature
                    ],
                )?;
                Ok(true) // Successfully merged
            }
        }
    }

    /// Exports all local records. Used when establishing a new P2P connection to synchronize state with peers.
    pub fn get_all_records(&self) -> Result<Vec<CrdtRecord>> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, author_id, timestamp, payload, signature FROM crdt_store")?;

        let record_iter = stmt.query_map([], |row| {
            Ok(CrdtRecord {
                id: row.get(0)?,
                author_id: row.get(1)?,
                timestamp: row.get(2)?,
                payload: row.get(3)?,
                signature: row.get(4)?,
            })
        })?;

        let mut records = Vec::new();
        for record in record_iter {
            records.push(record?);
        }

        Ok(records)
    }
}
