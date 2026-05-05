import json
import os
import time
from dataclasses import dataclass
from typing import Optional

import aiosqlite


SCHEMA = """
CREATE TABLE IF NOT EXISTS clients (
    client_id TEXT PRIMARY KEY,
    client_secret TEXT NOT NULL,
    client_name TEXT,
    redirect_uris TEXT NOT NULL,
    token_endpoint_auth_method TEXT NOT NULL DEFAULT 'client_secret_post',
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS pending_auth (
    code TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    code_challenge_method TEXT NOT NULL,
    state TEXT,
    resource TEXT,
    scope TEXT,
    csrf TEXT NOT NULL,
    approved INTEGER NOT NULL DEFAULT 0,
    expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS access_tokens (
    token TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    scope TEXT,
    expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    token TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    access_token TEXT NOT NULL,
    refresh_expires_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_pending_auth_expires ON pending_auth(expires_at);
CREATE INDEX IF NOT EXISTS idx_access_tokens_expires ON access_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires ON refresh_tokens(refresh_expires_at);
"""


@dataclass
class Client:
    client_id: str
    client_secret: str
    client_name: Optional[str]
    redirect_uris: list[str]
    token_endpoint_auth_method: str


@dataclass
class PendingAuth:
    code: str
    client_id: str
    redirect_uri: str
    code_challenge: str
    code_challenge_method: str
    state: Optional[str]
    resource: Optional[str]
    scope: Optional[str]
    csrf: str
    approved: bool
    expires_at: int


@dataclass
class AccessToken:
    token: str
    client_id: str
    scope: Optional[str]
    expires_at: int


@dataclass
class RefreshToken:
    token: str
    client_id: str
    access_token: str
    refresh_expires_at: int


class Storage:
    def __init__(self, db_path: str):
        self.db_path = db_path

    async def init(self) -> None:
        parent = os.path.dirname(self.db_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        async with aiosqlite.connect(self.db_path) as db:
            await db.executescript(SCHEMA)
            await db.commit()

    async def add_client(self, client: Client) -> None:
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "INSERT INTO clients(client_id, client_secret, client_name, "
                "redirect_uris, token_endpoint_auth_method, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    client.client_id,
                    client.client_secret,
                    client.client_name,
                    json.dumps(client.redirect_uris),
                    client.token_endpoint_auth_method,
                    int(time.time()),
                ),
            )
            await db.commit()

    async def get_client(self, client_id: str) -> Optional[Client]:
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute(
                "SELECT client_id, client_secret, client_name, redirect_uris, "
                "token_endpoint_auth_method FROM clients WHERE client_id = ?",
                (client_id,),
            ) as cur:
                row = await cur.fetchone()
        if not row:
            return None
        return Client(
            client_id=row[0],
            client_secret=row[1],
            client_name=row[2],
            redirect_uris=json.loads(row[3]),
            token_endpoint_auth_method=row[4],
        )

    async def add_pending_auth(self, p: PendingAuth) -> None:
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "INSERT INTO pending_auth(code, client_id, redirect_uri, "
                "code_challenge, code_challenge_method, state, resource, scope, "
                "csrf, approved, expires_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    p.code,
                    p.client_id,
                    p.redirect_uri,
                    p.code_challenge,
                    p.code_challenge_method,
                    p.state,
                    p.resource,
                    p.scope,
                    p.csrf,
                    1 if p.approved else 0,
                    p.expires_at,
                ),
            )
            await db.commit()

    async def get_pending_auth(self, code: str) -> Optional[PendingAuth]:
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute(
                "SELECT code, client_id, redirect_uri, code_challenge, "
                "code_challenge_method, state, resource, scope, csrf, approved, "
                "expires_at FROM pending_auth WHERE code = ?",
                (code,),
            ) as cur:
                row = await cur.fetchone()
        if not row:
            return None
        return PendingAuth(
            code=row[0],
            client_id=row[1],
            redirect_uri=row[2],
            code_challenge=row[3],
            code_challenge_method=row[4],
            state=row[5],
            resource=row[6],
            scope=row[7],
            csrf=row[8],
            approved=bool(row[9]),
            expires_at=row[10],
        )

    async def mark_pending_approved(self, code: str) -> None:
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "UPDATE pending_auth SET approved = 1 WHERE code = ?", (code,)
            )
            await db.commit()

    async def rotate_pending_csrf(self, code: str, new_csrf: str) -> None:
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "UPDATE pending_auth SET csrf = ? WHERE code = ?", (new_csrf, code)
            )
            await db.commit()

    async def consume_pending_auth(self, code: str) -> Optional[PendingAuth]:
        """Atomically read-and-delete a pending auth (single-use)."""
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute(
                "SELECT code, client_id, redirect_uri, code_challenge, "
                "code_challenge_method, state, resource, scope, csrf, approved, "
                "expires_at FROM pending_auth WHERE code = ?",
                (code,),
            ) as cur:
                row = await cur.fetchone()
            if not row:
                return None
            await db.execute("DELETE FROM pending_auth WHERE code = ?", (code,))
            await db.commit()
        return PendingAuth(
            code=row[0],
            client_id=row[1],
            redirect_uri=row[2],
            code_challenge=row[3],
            code_challenge_method=row[4],
            state=row[5],
            resource=row[6],
            scope=row[7],
            csrf=row[8],
            approved=bool(row[9]),
            expires_at=row[10],
        )

    async def add_access_token(self, t: AccessToken) -> None:
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "INSERT INTO access_tokens(token, client_id, scope, expires_at) "
                "VALUES (?, ?, ?, ?)",
                (t.token, t.client_id, t.scope, t.expires_at),
            )
            await db.commit()

    async def get_access_token(self, token: str) -> Optional[AccessToken]:
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute(
                "SELECT token, client_id, scope, expires_at "
                "FROM access_tokens WHERE token = ?",
                (token,),
            ) as cur:
                row = await cur.fetchone()
        if not row:
            return None
        return AccessToken(token=row[0], client_id=row[1], scope=row[2], expires_at=row[3])

    async def delete_access_token(self, token: str) -> None:
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("DELETE FROM access_tokens WHERE token = ?", (token,))
            await db.commit()

    async def add_refresh_token(self, r: RefreshToken) -> None:
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "INSERT INTO refresh_tokens(token, client_id, access_token, "
                "refresh_expires_at) VALUES (?, ?, ?, ?)",
                (r.token, r.client_id, r.access_token, r.refresh_expires_at),
            )
            await db.commit()

    async def consume_refresh_token(self, token: str) -> Optional[RefreshToken]:
        """Atomically read-and-delete a refresh token (full rotation)."""
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute(
                "SELECT token, client_id, access_token, refresh_expires_at "
                "FROM refresh_tokens WHERE token = ?",
                (token,),
            ) as cur:
                row = await cur.fetchone()
            if not row:
                return None
            await db.execute("DELETE FROM refresh_tokens WHERE token = ?", (token,))
            await db.commit()
        return RefreshToken(
            token=row[0],
            client_id=row[1],
            access_token=row[2],
            refresh_expires_at=row[3],
        )

    async def cleanup_expired(self) -> None:
        now = int(time.time())
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("DELETE FROM pending_auth WHERE expires_at < ?", (now,))
            await db.execute("DELETE FROM access_tokens WHERE expires_at < ?", (now,))
            await db.execute(
                "DELETE FROM refresh_tokens WHERE refresh_expires_at < ?", (now,)
            )
            await db.commit()
