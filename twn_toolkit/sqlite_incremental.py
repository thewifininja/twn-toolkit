"""Incremental SQLite TEXT/BLOB reads with an owned, read-only snapshot."""
import ctypes as C
import ctypes.util
import codecs
from contextlib import contextmanager
from functools import lru_cache
import os
from pathlib import Path


@lru_cache(maxsize=1)
def _api():
    import _sqlite3
    try:
        lib = C.CDLL(ctypes.util.find_library('sqlite3') or _sqlite3.__file__)
    except OSError as exc:
        raise ValueError('Incremental SQLite reading is unavailable on this runtime.') from exc
    pointer = C.c_void_p
    signatures = {
        'sqlite3_open_v2': ([C.c_char_p,C.POINTER(pointer),C.c_int,C.c_char_p],C.c_int),
        'sqlite3_close': ([pointer],C.c_int),
        'sqlite3_busy_timeout': ([pointer,C.c_int],C.c_int),
        'sqlite3_limit': ([pointer,C.c_int,C.c_int],C.c_int),
        'sqlite3_prepare_v2': ([pointer,C.c_char_p,C.c_int,C.POINTER(pointer),C.POINTER(C.c_char_p)],C.c_int),
        'sqlite3_bind_text': ([pointer,C.c_int,C.c_char_p,C.c_int,pointer],C.c_int),
        'sqlite3_bind_int64': ([pointer,C.c_int,C.c_int64],C.c_int),
        'sqlite3_step': ([pointer],C.c_int),
        'sqlite3_column_count': ([pointer],C.c_int),
        'sqlite3_column_type': ([pointer,C.c_int],C.c_int),
        'sqlite3_column_int64': ([pointer,C.c_int],C.c_int64),
        'sqlite3_column_double': ([pointer,C.c_int],C.c_double),
        'sqlite3_column_text': ([pointer,C.c_int],pointer),
        'sqlite3_column_bytes': ([pointer,C.c_int],C.c_int),
        'sqlite3_finalize': ([pointer],C.c_int),
        'sqlite3_blob_open': ([pointer,C.c_char_p,C.c_char_p,C.c_char_p,C.c_int64,C.c_int,C.POINTER(pointer)],C.c_int),
        'sqlite3_blob_bytes': ([pointer],C.c_int),
        'sqlite3_blob_read': ([pointer,pointer,C.c_int,C.c_int],C.c_int),
        'sqlite3_blob_close': ([pointer],C.c_int),
    }
    for name,(args,result) in signatures.items():
        fn=getattr(lib,name);fn.argtypes=args;fn.restype=result
    return lib


def _check(code):
    if code:
        raise ValueError(f'Could not read retained SQLite data (code {code}).')


class ReadSnapshot:
    """Owned read-only connection. No access to Python connection internals."""
    def __init__(self,path):
        self.lib=_api();self.db=C.c_void_p();self.blobs=set()
        code=self.lib.sqlite3_open_v2(os.fsencode(Path(path).resolve()),C.byref(self.db),1,None)
        if code:
            if self.db:self.lib.sqlite3_close(self.db)
            self.db=None;_check(code)
        try:
            _check(self.lib.sqlite3_busy_timeout(self.db,1000))
            # Bound ordinary metadata columns; blob I/O bypasses full cell copies.
            self.lib.sqlite3_limit(self.db,0,128*1024)
            self.query('BEGIN')
            self.encoding=self.query('PRAGMA encoding')[0][0]
        except BaseException:
            self.close();raise

    def query(self,sql,params=(),limit=1000):
        if not self.db:raise ValueError('Read snapshot is closed.')
        statement=C.c_void_p()
        try:
            _check(self.lib.sqlite3_prepare_v2(self.db,sql.encode(),-1,C.byref(statement),None))
            for index,value in enumerate(params,1):
                if isinstance(value,int):
                    _check(self.lib.sqlite3_bind_int64(statement,index,value))
                else:
                    raw=str(value).encode()
                    _check(self.lib.sqlite3_bind_text(statement,index,raw,len(raw),C.c_void_p(-1)))
            rows=[]
            while True:
                code=self.lib.sqlite3_step(statement)
                if code==101:break
                if code!=100:_check(code)
                if len(rows)>=limit:raise ValueError('Read metadata row limit exceeded.')
                row=[]
                for column in range(self.lib.sqlite3_column_count(statement)):
                    kind=self.lib.sqlite3_column_type(statement,column)
                    if kind==5:value=None
                    elif kind==1:value=self.lib.sqlite3_column_int64(statement,column)
                    elif kind==2:value=self.lib.sqlite3_column_double(statement,column)
                    else:
                        pointer=self.lib.sqlite3_column_text(statement,column)
                        size=self.lib.sqlite3_column_bytes(statement,column)
                        if size>128*1024:raise ValueError('Read metadata field limit exceeded.')
                        value=C.string_at(pointer,size).decode() if pointer else ''
                    row.append(value)
                rows.append(tuple(row))
            return rows
        finally:
            if statement:self.lib.sqlite3_finalize(statement)

    @contextmanager
    def _blob(self, table, column, rowid):
        if not self.db:
            raise ValueError('Read snapshot is closed.')
        blob=C.c_void_p()
        try:
            _check(self.lib.sqlite3_blob_open(self.db,b'main',table.encode(),column.encode(),int(rowid),0,C.byref(blob)))
            self.blobs.add(blob.value)
            yield blob
        finally:
            if blob and blob.value in self.blobs:
                self.blobs.remove(blob.value)
                self.lib.sqlite3_blob_close(blob)

    def blob_size(self, table, column, rowid):
        with self._blob(table, column, rowid) as blob:
            return self.lib.sqlite3_blob_bytes(blob)

    def iter_blob(self, table, column, rowid, *, maximum=None):
        with self._blob(table, column, rowid) as blob:
            size=self.lib.sqlite3_blob_bytes(blob)
            if maximum is not None and size>maximum:
                raise ValueError('Retained metadata exceeds the download limit.')
            for offset in range(0,size,65536):
                if blob.value not in self.blobs:
                    raise ValueError('Read snapshot is closed.')
                count=min(65536,size-offset);buffer=C.create_string_buffer(count)
                _check(self.lib.sqlite3_blob_read(blob,buffer,count,offset))
                yield buffer.raw

    def read_blob(self, table, column, rowid, *, cap, prefix=False):
        if not 0 <= cap <= 64*1024*1024:
            raise ValueError('Invalid retained metadata read limit.')
        with self._blob(table,column,rowid) as blob:
            size=self.lib.sqlite3_blob_bytes(blob)
            if size>cap and not prefix:
                return None,size
            length=min(size,cap);parts=[]
            for offset in range(0,length,65536):
                count=min(65536,length-offset);buffer=C.create_string_buffer(count)
                _check(self.lib.sqlite3_blob_read(blob,buffer,count,offset))
                parts.append(buffer.raw)
            return b''.join(parts),size

    def text_prefix(self, table, column, rowid, chars):
        data,size=self.read_blob(table,column,rowid,cap=chars*4,prefix=True)
        text=data.decode(self.encoding,errors='ignore')
        return text[:chars], size>len(data) or len(text)>chars

    def iter_utf8(self, table, column, rowid, *, maximum):
        decoder=codecs.getincrementaldecoder(self.encoding)()
        used=0
        chunks = self.iter_blob(table,column,rowid,maximum=maximum)
        try:
            for data in chunks:
                output=decoder.decode(data).encode('utf-8')
                used+=len(output)
                if used>maximum:
                    raise ValueError('Retained metadata exceeds the download limit.')
                yield output
            output=decoder.decode(b'',final=True).encode('utf-8')
            if used+len(output)>maximum:
                raise ValueError('Retained metadata exceeds the download limit.')
            if output:
                yield output
        finally:
            chunks.close()

    def close(self):
        if self.db:
            for blob in self.blobs:
                self.lib.sqlite3_blob_close(C.c_void_p(blob))
            self.blobs.clear()
            self.lib.sqlite3_close(self.db);self.db=None

    def __enter__(self):return self
    def __exit__(self,*args):self.close()
