import json
import os
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from twn_toolkit.backup_inputs import decode_backup_json, read_preview_file
from twn_toolkit.profile_backup import ConfigurationImportStore, encrypt_backup, decrypt_backup


def backup():
    return {'format':'twn-toolkit-profile-backup','version':1,'items':{'ping_profiles':[]}}


@pytest.mark.parametrize('raw',[b'['*66+b']'*66,b'['+b'0,'*500_001+b'0]'])
@pytest.mark.parametrize('encrypted',[False,True])
def test_input_complexity_is_rejected_before_json_decoder(raw, encrypted):
    envelope=encrypt_backup(raw,'fixture') if encrypted else None
    with patch('twn_toolkit.backup_source_reads.json.loads',side_effect=AssertionError('decoder reached')):
        with pytest.raises(ValueError,match='nesting|complex'):
            decrypt_backup(envelope,'fixture') if encrypted else decode_backup_json(raw)


def test_preview_file_size_is_checked_before_read(tmp_path):
    path=tmp_path/'preview.token'
    with path.open('wb') as stream:stream.truncate(129*1024**2)
    with patch('twn_toolkit.backup_inputs.os.read',side_effect=AssertionError('read oversized token')):
        with pytest.raises(ValueError,match='file limit'):read_preview_file(path)


@pytest.mark.parametrize('kind',['fifo','symlink'])
def test_preview_requires_one_regular_nonblocking_handle(tmp_path,kind):
    path=tmp_path/'preview.token'
    if kind=='fifo':os.mkfifo(path)
    else:
        source=tmp_path/'source';source.write_bytes(b'private');path.symlink_to(source)
    with pytest.raises((ValueError,OSError)):read_preview_file(path)


def test_preview_growth_is_bounded_and_handle_is_closed(tmp_path):
    path=tmp_path/'preview.token';path.write_bytes(b'1234')
    original=os.read;descriptors=[]
    def growing(descriptor,size):
        descriptors.append(descriptor)
        value=original(descriptor,size)
        if len(descriptors)==1:
            with path.open('ab') as writer:writer.write(b'x'*40)
        return value
    with patch('twn_toolkit.backup_inputs.MAX_PREVIEW_CIPHER_BYTES',16),patch('twn_toolkit.backup_inputs.os.read',side_effect=growing):
        with pytest.raises(ValueError,match='file limit'):read_preview_file(path)
    with pytest.raises(OSError):os.fstat(descriptors[0])


def test_preview_publication_uses_reservations_and_retains_only_ciphertext(tmp_path):
    previews=ConfigurationImportStore(str(tmp_path),'fixture-key')
    data=backup();data['items']['ping_profiles']=[{'name':'private-fixture-marker'}]
    token=previews.create(data,user_id='owner',encrypted_input=True,import_mode='merge')
    path=previews.directory/(token+'.token')
    assert path.stat().st_mode&0o777==0o600
    assert b'private-fixture-marker' not in path.read_bytes()
    assert previews.get(token,user_id='owner')['backup']==data
    assert not list((tmp_path/'.upload-reservations').glob('*/data'))
    with patch('twn_toolkit.uploads.shutil.disk_usage',return_value=SimpleNamespace(free=0)):
        with pytest.raises(ValueError):previews.create(data,user_id='owner',encrypted_input=True,import_mode='merge')
    assert list(previews.directory.glob('*.token'))==[path]
    assert not list((tmp_path/'.upload-reservations').glob('*/data'))


def test_another_user_cannot_invalidate_the_owners_preview(tmp_path):
    previews=ConfigurationImportStore(str(tmp_path),'fixture-key')
    token=previews.create(backup(),user_id='owner',encrypted_input=False,import_mode='merge')
    with pytest.raises(ValueError):previews.get(token,user_id='other')
    assert previews.get(token,user_id='owner')['backup']==backup()


def test_preview_complexity_failure_never_publishes_a_token(tmp_path):
    previews=ConfigurationImportStore(str(tmp_path),'fixture-key')
    data=backup();data['items']['ping_profiles']=[{'name':'fixture','payload':[0]*500_001}]
    with pytest.raises(ValueError,match='complex'):
        previews.create(data,user_id='owner',encrypted_input=False,import_mode='merge')
    assert not list(previews.directory.glob('*.token'))


def test_oversized_retained_preview_becomes_actionable_unavailable_error(tmp_path):
    previews=ConfigurationImportStore(str(tmp_path),'fixture-key')
    token=previews.create(backup(),user_id='owner',encrypted_input=False,import_mode='merge')
    with (previews.directory/(token+'.token')).open('wb') as stream:stream.truncate(129*1024**2)
    with patch.object(previews._cipher,'decrypt',side_effect=AssertionError('oversized ciphertext decrypted')):
        with pytest.raises(ValueError,match='no longer available'):previews.get(token,user_id='owner')


def test_full_preview_capacity_rejects_before_encryption(tmp_path):
    previews=ConfigurationImportStore(str(tmp_path),'fixture-key');previews.directory.mkdir()
    for index in range(100):(previews.directory/(f'{index:048x}.token')).write_bytes(b'fixture')
    with patch.object(previews._cipher,'encrypt',side_effect=AssertionError('encrypted before admission')):
        with pytest.raises(ValueError,match='capacity is full'):
            previews.create(backup(),user_id='owner',encrypted_input=False,import_mode='merge')
    assert len(list(previews.directory.glob('*.token')))==100
