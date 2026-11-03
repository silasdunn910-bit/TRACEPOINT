"""SQLite persistence with versioned migrations and foreign keys."""
from __future__ import annotations

import json
import os
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
    # v3: stored Intelligence Reports (snapshot generated when an investigation completes; reopenable).
    """
    CREATE TABLE intel_reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        investigation_id INTEGER NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
        status TEXT NOT NULL,
        engine_version TEXT NOT NULL,
        generated_at TEXT NOT NULL,
        payload TEXT NOT NULL DEFAULT '',
        error TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX idx_intel_reports_inv ON intel_reports(investigation_id);
    """,
    # v4: workflow stage records, persisted source registry (deduplicated per investigation), extra indexes.
    # Additive only: no existing table is altered or recreated.
    """
    CREATE TABLE investigation_stages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        investigation_id INTEGER NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
        seq INTEGER NOT NULL,
        stage TEXT NOT NULL,
        status TEXT NOT NULL,
        started_at TEXT NOT NULL,
        finished_at TEXT NOT NULL DEFAULT '',
        detail TEXT NOT NULL DEFAULT '',
        UNIQUE(investigation_id, stage)
    );
    CREATE TABLE source_registry (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        investigation_id INTEGER NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
        source_key TEXT NOT NULL,
        provider TEXT NOT NULL,
        url TEXT NOT NULL DEFAULT '',
        category TEXT NOT NULL DEFAULT '',
        retrieved_at TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL DEFAULT '',
        http_status TEXT NOT NULL DEFAULT '',
        consulted INTEGER NOT NULL DEFAULT 0,
        reliability TEXT NOT NULL DEFAULT '',
        finding_count INTEGER NOT NULL DEFAULT 0,
        finding_ids TEXT NOT NULL DEFAULT '',
        UNIQUE(investigation_id, source_key)
    );
    CREATE INDEX idx_stages_inv ON investigation_stages(investigation_id);
    CREATE INDEX idx_source_registry_inv ON source_registry(investigation_id);
    CREATE INDEX idx_sources_inv ON sources(investigation_id);
    CREATE INDEX idx_findings_source_url ON findings(source_url);
    CREATE INDEX idx_findings_category ON findings(category, confidence);
    CREATE INDEX idx_investigations_type ON investigations(inv_type, created_at);
    CREATE INDEX idx_history_inv ON search_history(investigation_id);
    CREATE INDEX idx_reports_inv ON reports(investigation_id);
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
            if 0 < current < len(MIGRATIONS) and self.conn.execute("SELECT COUNT(*) FROM investigations").fetchone()[0]:
                try:  # safety copy of existing data before any schema change
                    self.backup()
                except Exception:  # noqa: BLE001 - never block start-up on a backup problem
                    pass
            for i, sql in enumerate(MIGRATIONS, start=1):
                if i > current:
                    try:
                        self.conn.executescript("BEGIN;" + sql + f"INSERT INTO schema_version VALUES ({i});COMMIT;")
                    except BaseException:
                        self.conn.rollback()   # a failed step leaves the database at its previous version
                        raise

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
    def save_result(self, inv_type: str, target: str, result: ModuleResult, status: str = "") -> int:
        """Persist a result atomically: any failure rolls back so no partial investigation is kept
        (and cannot be committed later by an unrelated write on this connection)."""
        with self._lock:
            try:
                return self._save_result(inv_type, target, result, status)
            except BaseException:
                self.conn.rollback()
                raise

    def _save_result(self, inv_type: str, target: str, result: ModuleResult, status: str = "") -> int:
        ts = now_iso()
        ref = "TP-" + datetime.now().strftime("%Y%m%d") + "-" + uuid.uuid4().hex[:6].upper()
        with self._lock:
            cur = self.conn.execute(
                "INSERT INTO investigations(ref,inv_type,target,status,created_at,updated_at,notes) VALUES (?,?,?,?,?,?,?)",
                (ref, inv_type, target, status or ("complete" if not result.errors else "complete_with_errors"), ts, ts,
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

    # -- intelligence reports ---------------------------------------------------------
    def save_intel_report(self, inv_id: int, status: str, engine_version: str, payload: str, error: str = "") -> int:
        with self._lock:
            cur = self.conn.execute(
                "INSERT INTO intel_reports(investigation_id,status,engine_version,generated_at,payload,error) "
                "VALUES (?,?,?,?,?,?)", (inv_id, status, engine_version, now_iso(), payload, redact(error)))
            self.conn.commit()
            return cur.lastrowid

    def latest_intel_report(self, inv_id: int) -> sqlite3.Row | None:
        rows = self.q("SELECT * FROM intel_reports WHERE investigation_id=? ORDER BY id DESC LIMIT 1", (inv_id,))
        return rows[0] if rows else None

    def list_intel_reports(self, limit: int = 60) -> list[sqlite3.Row]:
        """Latest intelligence report per investigation (without the payload), newest first."""
        return self.q("""SELECT r.id, r.investigation_id, r.status, r.engine_version, r.generated_at, r.error,
                         i.ref, i.inv_type, i.target
                         FROM intel_reports r JOIN investigations i ON i.id=r.investigation_id
                         WHERE r.id IN (SELECT MAX(id) FROM intel_reports GROUP BY investigation_id)
                         ORDER BY r.id DESC LIMIT ?""", (limit,))

    # -- workflow stages & source registry ----------------------------------------------
    def save_stages(self, inv_id: int, stages: list[dict]) -> None:
        """Insert or update stage records (idempotent per investigation + stage)."""
        with self._lock:
            for seq, st in enumerate(stages, 1):
                self.conn.execute(
                    """INSERT INTO investigation_stages(investigation_id,seq,stage,status,started_at,finished_at,detail)
                    VALUES (?,?,?,?,?,?,?) ON CONFLICT(investigation_id,stage) DO UPDATE SET
                    seq=excluded.seq,status=excluded.status,started_at=excluded.started_at,
                    finished_at=excluded.finished_at,detail=excluded.detail""",
                    (inv_id, seq, st["stage"], st["status"], st["started_at"], st.get("finished_at", ""),
                     redact(st.get("detail", ""))[:1000]))
            self.conn.commit()

    def stages(self, inv_id: int) -> list[sqlite3.Row]:
        return self.q("SELECT * FROM investigation_stages WHERE investigation_id=? ORDER BY seq", (inv_id,))

    def replace_source_registry(self, inv_id: int, records: list[dict]) -> None:
        """The registry is derived from stored sources/findings, so it is rebuilt atomically per investigation."""
        with self._lock:
            try:
                self.conn.execute("DELETE FROM source_registry WHERE investigation_id=?", (inv_id,))
                for r in records:
                    self.conn.execute(
                        """INSERT OR IGNORE INTO source_registry(investigation_id,source_key,provider,url,category,
                        retrieved_at,status,http_status,consulted,reliability,finding_count,finding_ids)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (inv_id, r["source_key"], r["provider"], r["url"], r["category"], r["retrieved_at"],
                         r["status"], r["http_status"], 1 if r["consulted"] else 0, r["reliability"],
                         r["finding_count"], r["finding_ids"]))
                self.conn.commit()
            except BaseException:
                self.conn.rollback()
                raise

    def source_registry(self, inv_id: int) -> list[sqlite3.Row]:
        return self.q("SELECT * FROM source_registry WHERE investigation_id=? ORDER BY id", (inv_id,))

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
            return self._env_secret(name)
        try:
            value = decrypt_secret(rows[0]["secret"])
        except Exception:
            return ""
        register_secret(value)
        return value

    @staticmethod
    def _env_secret(name: str) -> str:
        """Fallback: the credential's environment variable (from the shell or a git-ignored .env file)."""
        from .configuration import ENV_VARS
        var = ENV_VARS.get(name)
        value = os.environ.get(var, "").strip() if var else ""
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
