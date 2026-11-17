"""SQLite 사용자 계정 및 활동기록 저장소."""
import hashlib
import hmac
import json
import re
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
import os
from zoneinfo import ZoneInfo

DB_PATH = Path(os.getenv("CONCERT_DB_PATH", str(Path(__file__).resolve().parent / "myproject.db")))
DB_PATH.parent.mkdir(parents=True, exist_ok=True)
PBKDF2_ROUNDS = 260_000
MAX_SNAPSHOT_BYTES = 1_000_000


def kst_now() -> str:
    return datetime.now(ZoneInfo("Asia/Seoul")).isoformat(timespec="seconds")


@contextmanager
def connect():
    db = sqlite3.connect(DB_PATH, timeout=20, check_same_thread=False)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA busy_timeout=20000")
    db.execute("PRAGMA foreign_keys=ON")
    try:
        yield db
        db.commit()
    except BaseException:
        db.rollback()
        raise
    finally:
        db.close()


def initialize():
    with connect() as db:
        db.execute("PRAGMA journal_mode=WAL")
        db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id_num INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                userid TEXT NOT NULL UNIQUE,
                passwd_hash BLOB NOT NULL,
                salt BLOB NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS groups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                owner_id INTEGER NOT NULL REFERENCES users(id_num),
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS group_members (
                group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
                user_id INTEGER NOT NULL REFERENCES users(id_num) ON DELETE CASCADE,
                status TEXT NOT NULL CHECK(status IN ('active','invited')),
                PRIMARY KEY(group_id,user_id)
            );
            CREATE TABLE IF NOT EXISTS group_records (
                group_id INTEGER PRIMARY KEY REFERENCES groups(id) ON DELETE CASCADE,
                snapshot_json TEXT NOT NULL DEFAULT '{}',
                version INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS user_records (
                user_id INTEGER PRIMARY KEY,
                snapshot_json TEXT NOT NULL DEFAULT '{}',
                updated_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id_num) ON DELETE CASCADE
            );
        """)


def register(username: str, userid: str, passwd: str) -> tuple[bool, str]:
    username, userid = username.strip(), userid.strip()
    if not (1 <= len(username) <= 40):
        return False, "이름은 1~40자로 입력하세요."
    if not re.fullmatch(r"[0-9]{4,15}", userid):
        return False, "학번은 숫자 4~15자리로 입력하세요."
    if len(passwd) < 8 or len(passwd) > 128:
        return False, "비밀번호는 8~128자로 입력하세요."
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", passwd.encode("utf-8"), salt, PBKDF2_ROUNDS)
    try:
        with connect() as db:
            cursor = db.execute(
                "INSERT INTO users(username, userid, passwd_hash, salt, created_at) VALUES (?, ?, ?, ?, ?)",
                (username, userid, digest, salt, kst_now()),
            )
            db.execute("INSERT INTO user_records(user_id,snapshot_json,updated_at) VALUES(?,?,?)", (cursor.lastrowid,"{}",kst_now()))
    except sqlite3.IntegrityError:
        return False, "이미 등록된 아이디입니다."
    return True, "등록되었습니다. 로그인해 주세요."


def userid_exists(userid: str) -> bool:
    """학번 중복 검사 (최종 가입 시 DB UNIQUE 제약으로 한 번 더 검사)."""
    with connect() as db:
        return db.execute("SELECT 1 FROM users WHERE userid=? LIMIT 1", (userid.strip(),)).fetchone() is not None


def authenticate(userid: str, passwd: str):
    with connect() as db:
        entry = db.execute(
            "SELECT id_num,userid,username,passwd_hash,salt FROM users WHERE userid=?",
            (userid.strip(),),
        ).fetchone()
    if entry is None:
        return None
    digest = hashlib.pbkdf2_hmac("sha256", passwd.encode("utf-8"), entry["salt"], PBKDF2_ROUNDS)
    if not hmac.compare_digest(digest, entry["passwd_hash"]):
        return None
    return {"id_num": entry["id_num"], "userid": entry["userid"], "username": entry["username"]}


def load_snapshot(user_id: int) -> dict:
    with connect() as db:
        row = db.execute("SELECT snapshot_json FROM user_records WHERE user_id=?",(user_id,)).fetchone()
    return json.loads(row["snapshot_json"]) if row else {}


def save_snapshot(user_id: int, userid: str, snapshot: dict) -> None:
    prefix = "gc-profile:" + userid + ":"
    if not isinstance(snapshot, dict) or len(snapshot) > 60:
        raise ValueError("저장 데이터 형식이 올바르지 않습니다.")
    filtered = {k:v for k,v in snapshot.items()
                if isinstance(k,str) and k.startswith(prefix) and isinstance(v,str) and len(k)<200}
    data = json.dumps(filtered,ensure_ascii=False,separators=(",",":"))
    if len(data.encode("utf-8")) > MAX_SNAPSHOT_BYTES:
        raise ValueError("저장 용량 한도를 초과했습니다.")
    with connect() as db:
        db.execute("""INSERT INTO user_records(user_id,snapshot_json,updated_at) VALUES(?,?,?)
           ON CONFLICT(user_id) DO UPDATE SET snapshot_json=excluded.snapshot_json, updated_at=excluded.updated_at""",
           (user_id,data,kst_now()))


def _active(db,user_id,group_id):
    return db.execute("SELECT 1 FROM group_members WHERE group_id=? AND user_id=? AND status='active'",(group_id,user_id)).fetchone() is not None

def group_info(user_id):
    with connect() as db:
        users=[dict(row) for row in db.execute("SELECT id_num, username, userid FROM users WHERE id_num!=? ORDER BY username, userid",(user_id,))]
        group_rows=db.execute("""SELECT g.id,g.name,(SELECT count(*) FROM group_members x WHERE x.group_id=g.id AND x.status='active') member_count
          FROM groups g JOIN group_members gm ON gm.group_id=g.id AND gm.user_id=? AND gm.status='active' ORDER BY g.id""",(user_id,)).fetchall()
        pending=[dict(row) for row in db.execute("""SELECT g.id,g.name,u.username owner_name FROM groups g JOIN users u ON u.id_num=g.owner_id
          JOIN group_members gm ON gm.group_id=g.id WHERE gm.user_id=? AND gm.status='invited'""",(user_id,))]
    return {"users":users,"groups":[dict(x) for x in group_rows],"pending":pending}

def active_group_detail(user_id,group_id):
    with connect() as db:
        row=db.execute("SELECT id,name,owner_id FROM groups WHERE id=?",(group_id,)).fetchone()
        if not row or not _active(db,user_id,group_id):return None
        members=[dict(x) for x in db.execute("""SELECT u.id_num,u.username,u.userid,CASE WHEN g.owner_id=u.id_num THEN 'owner' ELSE 'member' END role
           FROM group_members gm JOIN users u ON u.id_num=gm.user_id JOIN groups g ON g.id=gm.group_id
           WHERE gm.group_id=? AND gm.status='active' ORDER BY u.username""",(group_id,))]
        invited=[r[0] for r in db.execute("SELECT user_id FROM group_members WHERE group_id=? AND status='invited'",(group_id,))]
    return {"id":row['id'],"name":row['name'],"is_owner":row['owner_id']==user_id,"members":members,"invited":invited}

def create_group(user_id,name,members):
    name=str(name).strip()
    if not 1<=len(name)<=60: raise ValueError('모둠 이름은 1~60자로 입력하세요.')
    if len(members)>35:raise ValueError('초대 인원이 너무 많습니다.')
    with connect() as db:
        cur=db.execute('INSERT INTO groups(name,owner_id,created_at) VALUES(?,?,?)',(name,user_id,kst_now()))
        gid=cur.lastrowid
        db.execute('INSERT INTO group_members VALUES(?,?,?)',(gid,user_id,'active'))
        for uid in set(members):
            if uid==user_id:continue
            if not db.execute('SELECT 1 FROM users WHERE id_num=?',(uid,)).fetchone():continue
            db.execute('INSERT OR IGNORE INTO group_members VALUES(?,?,?)',(gid,uid,'invited'))
        db.execute('INSERT INTO group_records(group_id,snapshot_json,version,updated_at) VALUES(?,?,?,?)',(gid,'{}',0,kst_now()))
    return gid

def invite_members(user_id,group_id,members):
    with connect() as db:
        row=db.execute('SELECT owner_id FROM groups WHERE id=?',(group_id,)).fetchone()
        if not row or row['owner_id']!=user_id:raise ValueError('모둠장만 초대할 수 있습니다.')
        for uid in set(members):
            if uid==user_id:continue
            if db.execute('SELECT 1 FROM users WHERE id_num=?',(uid,)).fetchone():
                db.execute('INSERT OR IGNORE INTO group_members VALUES(?,?,?)',(group_id,uid,'invited'))

def respond_invite(user_id,group_id,accepted):
    with connect() as db:
        if not db.execute("SELECT 1 FROM group_members WHERE group_id=? AND user_id=? AND status='invited'",(group_id,user_id)).fetchone():
            raise ValueError('유효한 초대가 없습니다.')
        if accepted:db.execute("UPDATE group_members SET status='active' WHERE group_id=? AND user_id=?",(group_id,user_id))
        else:db.execute('DELETE FROM group_members WHERE group_id=? AND user_id=?',(group_id,user_id))

def leave_group(user_id,group_id):
    with connect() as db:
        row=db.execute('SELECT owner_id FROM groups WHERE id=?',(group_id,)).fetchone()
        if not row or not _active(db,user_id,group_id):raise ValueError('참여하지 않은 모둠입니다.')
        if row['owner_id']==user_id:raise ValueError('모둠장은 모둠을 탈퇴할 수 없습니다.')
        db.execute('DELETE FROM group_members WHERE group_id=? AND user_id=?',(group_id,user_id))

def group_snapshot(user_id,group_id):
    with connect() as db:
        if not _active(db,user_id,group_id): raise ValueError('모둠 접근 권한이 없습니다.')
        row=db.execute('SELECT snapshot_json,version FROM group_records WHERE group_id=?',(group_id,)).fetchone()
    if not row:return {},0
    return json.loads(row['snapshot_json']), row['version']

def save_group_patch(user_id,group_id,patch):
    if not isinstance(patch,dict) or len(patch)>50:raise ValueError('변경 데이터 형식이 올바르지 않습니다.')
    with connect() as db:
        db.execute('BEGIN IMMEDIATE')
        if not _active(db,user_id,group_id):raise ValueError('모둠 저장 권한이 없습니다.')
        row=db.execute('SELECT snapshot_json,version FROM group_records WHERE group_id=?',(group_id,)).fetchone()
        data=json.loads(row['snapshot_json']);version=row['version']
        # Updates are merged per storage key. Simultaneous modifications of the SAME key use last accepted write.
        for k,value in patch.items():
            if not isinstance(k,str) or not k.startswith('gc-shared:') or len(k)>200:continue
            if isinstance(value,dict) and value.get("kind")=="json_ops":
                try: current=json.loads(data.get(k,"{}"))
                except (ValueError,TypeError):current={}
                for operation in value.get("ops",[])[:250]:
                    path=operation.get("path",[])
                    if not path: current=operation.get("value");continue
                    parent=current
                    try:
                        for piece in path[:-1]:parent=parent[piece]
                        leaf=path[-1]
                        if operation.get("delete"):
                            if isinstance(parent,dict):parent.pop(leaf,None)
                            elif isinstance(parent,list) and isinstance(leaf,int) and 0<=leaf<len(parent):parent.pop(leaf)
                        else:parent[leaf]=operation.get("value")
                    except (KeyError,IndexError,TypeError):
                        # List or object structure changed remotely; replace the conflicting subdocument.
                        if len(path)==1 and isinstance(current,dict):current[path[0]]=operation.get("value")
                data[k]=json.dumps(current,ensure_ascii=False,separators=(",",":"))
            elif value is None:data.pop(k,None)
            elif isinstance(value,str):data[k]=value
        blob=json.dumps(data,ensure_ascii=False,separators=(',',':'))
        if len(blob.encode('utf8'))>MAX_SNAPSHOT_BYTES:raise ValueError('모둠 기록 저장 한도를 초과했습니다.')
        db.execute('UPDATE group_records SET snapshot_json=?, version=?, updated_at=? WHERE group_id=?',
                   (blob,version+1,kst_now(),group_id))
    return version+1


def save_personal_patch(user_id,userid,patch):
    if not isinstance(patch,dict) or len(patch)>60:raise ValueError('변경 데이터 형식이 올바르지 않습니다.')
    prefix='gc-profile:'+userid+':'
    with connect() as db:
        db.execute('BEGIN IMMEDIATE')
        row=db.execute('SELECT snapshot_json FROM user_records WHERE user_id=?',(user_id,)).fetchone()
        data=json.loads(row['snapshot_json']) if row else {}
        for k,v in patch.items():
            if not isinstance(k,str) or not k.startswith(prefix):continue
            if v is None:data.pop(k,None)
            elif isinstance(v,str):data[k]=v
            elif isinstance(v,dict) and v.get('kind')=='json_ops':
                try:doc=json.loads(data.get(k,'{}'))
                except (ValueError,TypeError):doc={}
                for op in v.get('ops',[])[:250]:
                    path=op.get('path',[])
                    if not path:doc=op.get('value');continue
                    parent=doc
                    try:
                        for piece in path[:-1]:parent=parent[piece]
                        if op.get('delete'):
                            if isinstance(parent,dict):parent.pop(path[-1],None)
                            elif isinstance(parent,list):parent.pop(path[-1])
                        else:parent[path[-1]]=op.get('value')
                    except (KeyError,IndexError,TypeError):
                        if len(path)==1 and isinstance(doc,dict):doc[path[0]]=op.get('value')
                data[k]=json.dumps(doc,ensure_ascii=False,separators=(',',':'))
        blob=json.dumps(data,ensure_ascii=False,separators=(',',':'))
        if len(blob.encode('utf8'))>MAX_SNAPSHOT_BYTES:raise ValueError('개인 저장 용량 한도 초과')
        db.execute('UPDATE user_records SET snapshot_json=?,updated_at=? WHERE user_id=?',(blob,kst_now(),user_id))
