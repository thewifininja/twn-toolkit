"""Portable exports stop before unbounded serialization or encryption."""
from export_job_helpers import run_export

import json
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from twn_toolkit import create_app
from twn_toolkit.profile_backup import (
    MAX_BACKUP_WIRE_BYTES, MAX_ENCRYPTED_BACKUP_PLAINTEXT_BYTES,
    build_profile_backup, encode_backup_json, encrypt_backup,
)


@pytest.mark.parametrize('value', [None, [True, False, 1.5], {'text': '\x00\\\"é😀' * 100},
                                  {'nested': [{'x': [1, 2, 3]}]}])
def test_json_encoding_preserves_format_and_exact_boundary(value):
    expected = json.dumps(value, indent=2).encode()
    assert encode_backup_json(value, len(expected)) == expected
    with pytest.raises(ValueError, match='too large'):
        encode_backup_json(value, len(expected) - 1)


def test_oversized_scalar_rejected_before_full_scalar_encoding():
    with patch('twn_toolkit.profile_backup.json.JSONEncoder.iterencode', side_effect=AssertionError('encoder reached')):
        with pytest.raises(ValueError, match='too large'):
            encode_backup_json({'secret': '\x00' * 200_000}, 1000)


def test_excessive_depth_rejected():
    value = []
    for _ in range(66):
        value = [value]
    with pytest.raises(ValueError, match='nesting'):
        encode_backup_json(value)


def item(identity, records):
    return dict(id=identity, label=identity, category='Tests', sensitive=False,
                store=SimpleNamespace(all=Mock(return_value=records)))


def test_aggregate_group_budget_stops_before_reading_later_store():
    groups = [item(str(i), [{'name': 'x' * 100}]) for i in range(3)]
    with pytest.raises(ValueError, match='too large'):
        build_profile_backup(groups, max_bytes=200)
    groups[0]['store'].all.assert_called_once()
    groups[1]['store'].all.assert_called_once()
    groups[2]['store'].all.assert_not_called()


def test_fernet_plaintext_cap_leaves_room_for_wire_envelope():
    size = MAX_ENCRYPTED_BACKUP_PLAINTEXT_BYTES
    ciphertext_size = ((57 + (size // 16 + 1) * 16 + 2) // 3) * 4
    envelope = encode_backup_json(encrypt_backup(b'', 'fixture'))
    empty_ciphertext_size = len(json.loads(envelope)['ciphertext'])
    assert ciphertext_size + len(envelope) - empty_ciphertext_size <= MAX_BACKUP_WIRE_BYTES


@pytest.mark.parametrize('encrypted', [False, True])
def test_export_bound_returns_actionable_error_without_encryption(tmp_path, encrypted):
    app = create_app(str(tmp_path))
    app.testing = True
    data = {'item': 'ping_profiles'}
    if encrypted:
        data.update(encrypt_backup='on', backup_password='fixture', confirm_backup_password='fixture')
    with patch('twn_toolkit.export_jobs.MAX_BACKUP_WIRE_BYTES', 100), patch('twn_toolkit.export_jobs.MAX_ENCRYPTED_BACKUP_PLAINTEXT_BYTES', 80), patch('twn_toolkit.export_jobs.encrypt_backup') as encrypt:
        client=app.test_client()
        result=run_export(client,client.post('/settings/backup/export',data=data))
    assert result['state']=='failed' and 'Export fewer groups' in result['error']
    encrypt.assert_not_called()
