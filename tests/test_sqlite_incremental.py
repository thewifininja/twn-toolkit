import json
import sqlite3
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from twn_toolkit.sqlite_incremental import ReadSnapshot
from twn_toolkit.retained_json import decode_retained_json


@pytest.fixture
def database(tmp_path):
    path = tmp_path/'fixture.db'
    with sqlite3.connect(path) as db:
        db.execute('PRAGMA journal_mode=WAL')
        db.execute('CREATE TABLE sample (id TEXT PRIMARY KEY, payload TEXT)')
        db.execute('INSERT INTO sample VALUES (?,?)', ('fixture', '"中文😀\\nvalue"'))
    return path


def test_size_gate_prefix_and_exact_unicode(database):
    with ReadSnapshot(database) as read:
        rowid = read.query('SELECT rowid FROM sample WHERE id=?', ('fixture',))[0][0]
        data, size = read.read_blob('sample','payload',rowid,cap=1000)
        assert decode_retained_json(data,read.encoding) == '中文😀\nvalue'
        assert read.read_blob('sample','payload',rowid,cap=1) == (None,size)
        assert read.read_blob('sample','payload',rowid,cap=1,prefix=True) == (b'"',size)
        assert b''.join(read.iter_utf8('sample','payload',rowid,maximum=1000)) == data
        assert not read.blobs
    assert read.db is None


def test_snapshot_does_not_follow_concurrent_replacement(database):
    with ReadSnapshot(database) as read:
        rowid = read.query('SELECT rowid FROM sample WHERE id=?',('fixture',))[0][0]
        old, _ = read.read_blob('sample','payload',rowid,cap=1000)
        with sqlite3.connect(database) as writer:
            writer.execute('UPDATE sample SET payload=? WHERE id=?', ('new data','fixture'))
        assert read.read_blob('sample','payload',rowid,cap=1000)[0] == old
    with ReadSnapshot(database) as fresh:
        assert fresh.read_blob('sample','payload',rowid,cap=1000)[0] == b'new data'


def test_close_during_partial_iteration_releases_all_handles(database):
    with sqlite3.connect(database) as db:
        db.execute('UPDATE sample SET payload=?', ('x'*200_000,))
    read=ReadSnapshot(database);stream=read.iter_blob('sample','payload',1)
    assert len(next(stream))==65536 and read.blobs
    read.close();assert read.db is None and not read.blobs
    with pytest.raises(ValueError,match='closed'):
        next(stream)
    stream.close();read.close()
    with pytest.raises(ValueError,match='closed'):
        read.query('SELECT 1')


def test_read_failure_and_bad_queries_release_handles(database):
    with ReadSnapshot(database) as read:
        with patch.object(read.lib,'sqlite3_blob_read',return_value=4):
            with pytest.raises(ValueError):
                read.read_blob('sample','payload',1,cap=1000)
        assert not read.blobs
        with pytest.raises(ValueError):read.query('SELECT missing FROM sample')
        assert read.query('SELECT count(*) FROM sample') == [(1,)]
        with pytest.raises(ValueError):read.read_blob('sample','missing',1,cap=1)
        assert not read.blobs


@pytest.mark.parametrize('encoding', ['UTF-16le','UTF-16be'])
def test_utf16_storage_is_decoded_and_downloaded_as_utf8(tmp_path,encoding):
    path=tmp_path/'utf.db'
    with sqlite3.connect(path) as db:
        db.execute(f"PRAGMA encoding='{encoding}'")
        db.execute('CREATE TABLE sample (payload TEXT)')
        db.execute('INSERT INTO sample VALUES (?)', ('"中文😀"',))
    with ReadSnapshot(path) as read:
        data,_=read.read_blob('sample','payload',1,cap=1000)
        assert decode_retained_json(data,read.encoding)=='中文😀'
        assert read.query('SELECT payload FROM sample') == [('"中文😀"',)]
        assert b''.join(read.iter_utf8('sample','payload',1,maximum=1000))=='"中文😀"'.encode()


def test_metadata_query_rejects_large_cell_and_blob_gate_avoids_native_copy(database):
    with sqlite3.connect(database) as db:
        db.execute('UPDATE sample SET payload=zeroblob(?)',(64*1024*1024,))
    with ReadSnapshot(database) as read:
        with pytest.raises(ValueError):read.query('SELECT payload FROM sample')
        assert read.read_blob('sample','payload',1,cap=1024)==(None,64*1024*1024)
    if not Path('/proc/self/status').exists():
        return
    program = '''from pathlib import Path
from twn_toolkit.sqlite_incremental import ReadSnapshot
import sys,json
def hwm():return int(next(l.split()[1] for l in Path('/proc/self/status').read_text().splitlines() if l.startswith('VmHWM:')))
before=hwm()
with ReadSnapshot(sys.argv[1]) as read:
 assert read.read_blob('sample','payload',1,cap=1024)==(None,64*1024*1024)
 assert len(read.read_blob('sample','payload',1,cap=1024,prefix=True)[0])==1024
print(json.dumps({'increase_kib':hwm()-before}))
'''
    response=subprocess.run([sys.executable,'-c',program,str(database)],capture_output=True,text=True,timeout=15,check=True)
    assert json.loads(response.stdout)['increase_kib'] < 8*1024


def test_json_complexity_is_rejected_before_decoder():
    with patch('twn_toolkit.retained_json.json.loads',side_effect=AssertionError('must not decode')):
        with pytest.raises(ValueError,match='64 levels'):
            decode_retained_json(b'['*66+b']'*66)
        with pytest.raises(ValueError,match='too complex'):
            decode_retained_json(b'['+b'0,'*500_001+b'0]')
    assert decode_retained_json(b'["braces [{ \\\" ok",null,1]') == ['braces [{ " ok',None,1]


def test_utf8_iterator_close_releases_blob_without_closing_snapshot(database):
    with sqlite3.connect(database) as db:
        db.execute('UPDATE sample SET payload=?',('x'*200000,))
    with ReadSnapshot(database) as read:
        stream=read.iter_utf8('sample','payload',1,maximum=300000)
        next(stream);assert read.blobs
        stream.close();assert not read.blobs
        assert read.query('SELECT 1')==[(1,)]
