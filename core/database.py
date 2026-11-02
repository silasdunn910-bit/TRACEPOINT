"""SQLite persistence with versioned migrations and foreign keys."""
from __future__ import annotations

import json
import shutil
import sqlite3
import threading
import uuid
from datetime import datetime
from pathlib import Path

from .configuration import BACKUP_DIR, DB_PATH
from .models import ModuleResult, now_iso
from .security import decrypt_secret, encrypt_secret, redact, register_secret

MIGRATIONS: list[str] = [
    # v1 -------------------------------------------------------------------
    """
    CREATE TABLE investigations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ref TEXT NOT NULL UNIQUE,
        inv_type TEXT NOT NULL,
        target TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'complete',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        notes TEXT DEFAULT '',
        ai_summary TEXT DEFAULT ''
    );
    CREATE TABLE sources (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        investigation_id INTEGER NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        url TEXT DEFAULT '',
        status TEXT NOT NULL,
        detail TEXT DEFAULT '',
        consulted_at TEXT NOT NULL
    );
    CREATE TABLE findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        investigation_id INTEGER NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
        fingerprint TEXT NOT NULL,
        category TEXT NOT NULL,
        title TEXT NOT NULL,
        value TEXT DEFAULT '',
        description TEXT NOT NULL,
        source TEXT NOT NULL,
        source_url TEXT DEFAULT '',
        confidence TEXT NOT NULL,
        evidence TEXT DEFAULT '',
        limitations TEXT DEFAULT '',
        discovered_at TEXT NOT NULL,
        UNIQUE(investigation_id, fingerprint)
    );
    CREATE TABLE entities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        entity_type TEXT NOT NULL,
        value TEXT NOT NULL,
        norm TEXT NOT NULL,
        verification TEXT NOT NULL DEFAULT 'UNVERIFIED',
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        UNIQUE(entity_type, norm)
    );
    CREATE TABLE investigation_entities (
        investigation_id INTEGER NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
        entity_id INTEGER NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
        source TEXT DEFAULT '',
        PRIMARY KEY (investigation_id, entity_id)
    );
    CREATE TABLE relationships (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        investigation_id INTEGER NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
        src_entity_id INTEGER NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
        dst_entity_id INTEGER NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
        rel_type TEXT NOT NULL,
        confidence TEXT NOT NULL,
        source TEXT DEFAULT '',
        created_at TEXT NOT NULL,
        UNIQUE(investigation_id, src_entity_id, dst_entity_id, rel_type)
    );
    CREATE TABLE search_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        query TEXT NOT NULL,
        detected_type TEXT,
        investigation_id INTEGER REFERENCES investigations(id) ON DELETE SET NULL,
        searched_at TEXT NOT NULL
    );
    CREATE TABLE reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        investigation_id INTEGER NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
        format TEXT NOT NULL,
        path TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    CREATE TABLE api_config (
        name TEXT PRIMARY KEY,
        secret TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    CREATE TABLE settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );
    CREATE TABLE image_hashes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        investigation_id INTEGER NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
        label TEXT NOT NULL,
        sha256 TEXT NOT NULL,
        phash TEXT, dhash TEXT, ahash TEXT,
        created_at TEXT NOT NULL
    );
    CREATE TABLE document_meta (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        investigation_id INTEGER NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
        label TEXT NOT NULL,
        sha256 TEXT NOT NULL,
        meta_json TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    CREATE INDEX idx_findings_inv ON findings(investigation_id);
    CREATE INDEX idx_rel_inv ON relationships(investigation_id);
    CREATE INDEX idx_ie_entity ON investigation_entities(entity_id);
    """,
    # v2: preserve search provenance and publication metadata for investigations.
    """
    ALTER TABLE findings ADD COLUMN query TEXT DEFAULT '';
    ALTER TABLE findings ADD COLUMN source_type TEXT DEFAULT '';
    ALTER TABLE findings ADD COLUMN published_at TEXT DEFAULT '';
    """,
]


class Database:
    def __init__(self, path: Path = DB_PATH):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA journal_mode = WAL")
        self.migrate()

    # -- schema -------------------------------------------------------------
    def migrate(self):
        with self._lock:
            self.conn.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)")
            row = self.conn.execute("SELECT MAX(version) v FROM schema_version").fetchone()
            current = row["v"] or 0
            for i, sql in enumerate(MIGRATIONS, start=1):
                if i > current:
                    self.conn.executescript("BEGIN;" + sql + f"INSERT INTO schema_version VALUES ({i});COMMIT;")

    def schema_version(self) -> int:
        return self.conn.execute("SELECT MAX(version) v FROM schema_version").fetchone()["v"] or 0

    def backup(self) -> Path:
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        dest = BACKUP_DIR / f"tracepoint-{stamp}.db"
        with self._lock:
            out = sqlite3.connect(dest)
            self.conn.backup(out)
            out.close()
        backups = sorted(BACKUP_DIR.glob("tracepoint-*.db"))
        for old in backups[:-10]:  # keep last 10
            old.unlink(missing_ok=True)
        return dest

    def close(self):
        with self._lock:
            self.conn.close()

    def q(self, sql: str, args=()) -> list[sqlite3.Row]:
        with self._lock:
            return self.conn.execute(sql, args).fetchall()

    # -- entities -----------------------------------------------------------
    def upsert_entity(self, etype: str, value: str, verification: str = "UNVERIFIED") -> int:
        norm = value.strip().lower()
        ts = now_iso()
        with self._lock:
            row = self.conn.execute("SELECT id, verification FROM entities WHERE entity_type=? AND norm=?",
                                    (etype, norm)).fetchone()
            if row:
                ver = verification if verification == "VERIFIED" else row["verification"]
                self.conn.execute("UPDATE entities SET last_seen=?, verification=? WHERE id=?", (ts, ver, row["id"]))
                return row["id"]
            cur = self.conn.execute(
                "INSERT INTO entities(entity_type,value,norm,verification,first_seen,last_seen) VALUES (?,?,?,?,?,?)",
                (etype, value.strip(), norm, verification, ts, ts))
            return cur.lastrowid

    # -- investigations -------------------------------------------------------
    def save_result(self, inv_type: str, target: str, result: ModuleResult) -> int:
        """Persist a result atomically: any failure rolls back so no partial investigation is kept
        (and cannot be committed later by an unrelated write on this connection)."""
        with self._lock:
            try:
                return self._save_result(inv_type, target, result)
            except BaseException:
                self.conn.rollback()
                raise

    def _save_result(self, inv_type: str, target: str, result: ModuleResult) -> int:
        ts = now_iso()
        ref = "TP-" + datetime.now().strftime("%Y%m%d") + "-" + uuid.uuid4().hex[:6].upper()
        with self._lock:
            cur = self.conn.execute(
                "INSERT INTO investigations(ref,inv_type,target,status,created_at,updated_at,notes) VALUES (?,?,?,?,?,?,?)",
                (ref, inv_type, target, "complete" if not result.errors else "complete_with_errors", ts, ts,
                 redact("\n".join(result.notes))))
            inv_id = cur.lastrowid
            for s in result.sources:
                self.conn.execute(
                    "INSERT INTO sources(investigation_id,name,url,status,detail,consulted_at) VALUES (?,?,?,?,?,?)",
                    (inv_id, s.name, s.url, s.status, redact(s.detail), s.consulted_at))
            for f in result.findings:
                self.conn.execute(
                    """INSERT OR IGNORE INTO findings(investigation_id,fingerprint,category,title,value,description,
                    source,source_url,confidence,evidence,limitations,discovered_at,query,source_type,published_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (inv_id, f.fingerprint(), f.category, f.title, f.value, f.description, f.source, f.source_url,
                     f.confidence, f.evidence, f.limitations, f.discovered_at, f.query, f.source_type, f.published_at))
            ids: dict[tuple, int] = {}
            for e in result.entities:
                eid = self.upsert_entity(e.type, e.value, e.verification)
                ids[e.key] = eid
                self.conn.execute("INSERT OR IGNORE INTO investigation_entities VALUES (?,?,?)", (inv_id, eid, e.source))
            for r in result.relationships:
                for ref_ in (r.src, r.dst):
                    if ref_.key not in ids:
                        eid = self.upsert_entity(ref_.type, ref_.value, ref_.verification)
                        ids[ref_.key] = eid
                        self.conn.execute("INSERT OR IGNORE INTO investigation_entities VALUES (?,?,?)",
                                          (inv_id, eid, ref_.source))
                self.conn.execute(
                    """INSERT OR IGNORE INTO relationships(investigation_id,src_entity_id,dst_entity_id,rel_type,
                    confidence,source,created_at) VALUES (?,?,?,?,?,?,?)""",
                    (inv_id, ids[r.src.key], ids[r.dst.key], r.rel_type, r.confidence, r.source, ts))
            self.conn.execute("INSERT INTO search_history(query,detected_type,investigation_id,searched_at) VALUES (?,?,?,?)",
                              (target, inv_type, inv_id, ts))
            self.conn.commit()
        return inv_id

    def list_investigations(self, limit: int = 50) -> list[sqlite3.Row]:
        return self.q("""SELECT i.*, (SELECT COUNT(*) FROM findings f WHERE f.investigation_id=i.id) n_findings
                         FROM investigations i ORDER BY i.id DESC LIMIT ?""", (limit,))

    def get_investigation(self, inv_id: int) -> sqlite3.Row | None:
        rows = self.q("SELECT * FROM investigations WHERE id=?", (inv_id,))
        return rows[0] if rows else None

    def find_investigation(self, key: str) -> sqlite3.Row | None:
        key = key.strip()
        rows = self.q("SELECT * FROM investigations WHERE ref=? COLLATE NOCASE OR CAST(id AS TEXT)=?", (key, key))
        return rows[0] if rows else None

    def findings(self, inv_id: int) -> list[sqlite3.Row]:
        order = "CASE confidence WHEN 'VERIFIED' THEN 0 WHEN 'STRONG' THEN 1 WHEN 'CORROBORATED' THEN 1 WHEN 'MODERATE' THEN 2 WHEN 'LOW' THEN 3 WHEN 'UNVERIFIED' THEN 4 ELSE 5 END"
        return self.q(f"SELECT * FROM findings WHERE investigation_id=? ORDER BY category, {order}, id", (inv_id,))

    def sources(self, inv_id: int) -> list[sqlite3.Row]:
        return self.q("SELECT * FROM sources WHERE investigation_id=? ORDER BY id", (inv_id,))

    def entities_for(self, inv_id: int) -> list[sqlite3.Row]:
        return self.q("""SELECT e.* FROM entities e JOIN investigation_entities ie ON ie.entity_id=e.id
                         WHERE ie.investigation_id=? ORDER BY e.entity_type, e.value""", (inv_id,))

    def relationships_for(self, inv_id: int) -> list[sqlite3.Row]:
        return self.q("""SELECT r.*, s.entity_type src_type, s.value src_value, d.entity_type dst_type, d.value dst_value
                         FROM relationships r JOIN entities s ON s.id=r.src_entity_id JOIN entities d ON d.id=r.dst_entity_id
                         WHERE r.investigation_id=? ORDER BY r.id""", (inv_id,))

    def delete_investigation(self, inv_id: int):
        with self._lock:
            self.conn.execute("DELETE FROM investigations WHERE id=?", (inv_id,))
            # remove entities no longer referenced by any investigation
            self.conn.execute("DELETE FROM entities WHERE id NOT IN (SELECT entity_id FROM investigation_entities)")
            self.conn.commit()

    def set_ai_summary(self, inv_id: int, text: str):
        with self._lock:
            self.conn.execute("UPDATE investigations SET ai_summary=?, updated_at=? WHERE id=?", (text, now_iso(), inv_id))
            self.conn.commit()

    def add_report(self, inv_id: int, fmt: str, path: str):
        with self._lock:
            self.conn.execute("INSERT INTO reports(investigation_id,format,path,created_at) VALUES (?,?,?,?)",
                              (inv_id, fmt, path, now_iso()))
            self.conn.commit()

    def reports(self) -> list[dict]:
        """Report rows with `path` resolved against the current REPORTS_DIR.

        Older rows stored absolute paths from a previous install location; only the
        file name is trusted, so they resolve correctly. Stored rows are not modified.
        `exists` tells the UI whether the file is actually on disk.
        """
        from pathlib import PureWindowsPath
        from core.configuration import REPORTS_DIR
        rows = self.q("""SELECT r.*, i.ref, i.target FROM reports r JOIN investigations i ON i.id=r.investigation_id
                         ORDER BY r.id DESC LIMIT 100""")
        out = []
        for r in rows:
            d = dict(r)
            p = REPORTS_DIR / PureWindowsPath(d["path"]).name
            d["path"], d["exists"] = str(p), p.is_file()
            out.append(d)
        return out

    def search_history(self, limit: int = 30) -> list[sqlite3.Row]:
        return self.q("SELECT * FROM search_history ORDER BY id DESC LIMIT ?", (limit,))

    def stats(self) -> dict:
        one = lambda sql: self.q(sql)[0][0]
        return {
            "investigations": one("SELECT COUNT(*) FROM investigations"),
            "findings": one("SELECT COUNT(*) FROM findings"),
            "verified": one("SELECT COUNT(*) FROM findings WHERE confidence='VERIFIED'"),
            "entities": one("SELECT COUNT(*) FROM entities"),
            "relationships": one("SELECT COUNT(*) FROM relationships"),
        }

    # -- image / document fingerprints ------------------------------------------
    def add_image_hash(self, inv_id: int, label: str, sha256: str, phash: str, dhash: str, ahash: str):
        with self._lock:
            self.conn.execute("INSERT INTO image_hashes(investigation_id,label,sha256,phash,dhash,ahash,created_at) VALUES (?,?,?,?,?,?,?)",
                              (inv_id, label, sha256, phash, dhash, ahash, now_iso()))
            self.conn.commit()

    def add_document_meta(self, inv_id: int, label: str, sha256: str, meta: dict):
        with self._lock:
            self.conn.execute("INSERT INTO document_meta(investigation_id,label,sha256,meta_json,created_at) VALUES (?,?,?,?,?)",
                              (inv_id, label, sha256, json.dumps(meta, default=str), now_iso()))
            self.conn.commit()

    # -- settings & secrets -----------------------------------------------------
    def get_setting(self, key: str, default: str = "") -> str:
        rows = self.q("SELECT value FROM settings WHERE key=?", (key,))
        return rows[0]["value"] if rows else default

    def set_setting(self, key: str, value: str):
        with self._lock:
            self.conn.execute("INSERT INTO settings(key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                              (key, value))
            self.conn.commit()

    def set_secret(self, name: str, value: str):
        register_secret(value)
        with self._lock:
            self.conn.execute("""INSERT INTO api_config(name,secret,updated_at) VALUES (?,?,?)
                                 ON CONFLICT(name) DO UPDATE SET secret=excluded.secret, updated_at=excluded.updated_at""",
                              (name, encrypt_secret(value), now_iso()))
            self.conn.commit()

    def get_secret(self, name: str) -> str:
        rows = self.q("SELECT secret FROM api_config WHERE name=?", (name,))
        if not rows:
            return ""
        try:
            value = decrypt_secret(rows[0]["secret"])
        except Exception:
            return ""
        register_secret(value)
        return value

    def delete_secret(self, name: str):
        with self._lock:
            self.conn.execute("DELETE FROM api_config WHERE name=?", (name,))
            self.conn.commit()

    def secret_names(self) -> dict[str, str]:
        return {r["name"]: r["updated_at"] for r in self.q("SELECT name, updated_at FROM api_config")}


_db: Database | None = None


def get_db() -> Database:
    global _db
    if _db is None:
        _db = Database()
    return _db
