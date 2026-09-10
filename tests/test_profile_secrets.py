import json
import sqlite3
import os
import stat
import subprocess
import sys
from unittest.mock import patch
from functools import partial

import pytest

from twn_toolkit.profiles import (
    ProfileStore, FortiAuthenticatorProfileStore, RadiusProfileStore, SNMPCredentialProfileStore,
)

SECRET_STORES = [
    (ProfileStore, 'api_key'), (FortiAuthenticatorProfileStore, 'password'),
    (partial(RadiusProfileStore, kind='servers'), 'secret'),
    (partial(RadiusProfileStore, kind='credentials'), 'password'),
    (SNMPCredentialProfileStore, 'community'), (SNMPCredentialProfileStore, 'auth_key'),
    (SNMPCredentialProfileStore, 'priv_key'),
]


def storage_path(store):
    return store.mso_store().path if getattr(store, '_uses_mso', False) else store.path


@pytest.mark.parametrize('store_type,field', SECRET_STORES)
def test_saved_secret_is_protected_without_changing_store_contract(tmp_path, store_type, field):
    store = store_type(str(tmp_path))
    profile = {'name': 'Lab', field: 'private-fixture-secret', 'host': 'https://example.com'}
    store.upsert(profile)
    assert profile[field] == 'private-fixture-secret'
    assert b'private-fixture-secret' not in storage_path(store).read_bytes()
    assert stat.S_IMODE(storage_path(store).stat().st_mode) == 0o600
    assert store.get('Lab') == profile
    assert store.duplicate('Lab')[field] == profile[field]
    assert store.get('Lab copy')[field] == profile[field]
    store.upsert({**profile, field: 'replacement-secret'})
    assert store.get('Lab')[field] == 'replacement-secret'
    assert b'replacement-secret' not in storage_path(store).read_bytes()


def test_legacy_read_is_nonmutating_and_any_write_protects_all_rows(tmp_path):
    store = ProfileStore(str(tmp_path))
    legacy = [{'name': 'A', 'api_key': 'legacy-secret'}, {'name': 'B', 'api_key': 'second-secret'}]
    store.path.write_text(json.dumps(legacy))
    original = store.path.read_bytes()
    assert store.all() == legacy
    assert store.path.read_bytes() == original
    assert not (tmp_path / 'session_secret').exists()
    store.upsert({'name': 'C', 'api_key': ''})
    assert 'legacy-secret' not in store.path.read_text()
    assert 'second-secret' not in store.path.read_text()
    assert store.get('A')['api_key'] == 'legacy-secret'
    assert store.get('C')['api_key'] == ''


@pytest.mark.parametrize('change', ['key', 'missing_key', 'name', 'file', 'token', 'version'])
def test_unreadable_or_moved_secret_fails_without_overwriting_profiles(tmp_path, change):
    store = ProfileStore(str(tmp_path))
    store.upsert({'name': 'A', 'api_key': 'original-secret'})
    raw = json.loads(store.path.read_text())
    if change == 'key':
        (tmp_path / 'session_secret').write_text('wrong-instance-key')
    elif change == 'missing_key':
        (tmp_path / 'session_secret').unlink()
    elif change == 'name':
        raw[0]['name'] = 'Other'
    elif change == 'file':
        store = ProfileStore(str(tmp_path), filename='other-profiles.json')
    elif change == 'token':
        raw[0]['api_key']['token'] = 'broken'
    else:
        raw[0]['api_key']['format'] = 'unknown-version'
    store.path.write_text(json.dumps(raw))
    before = store.path.read_bytes()
    with pytest.raises(ValueError, match='could not be decrypted'):
        store.upsert({'name': 'B', 'api_key': 'new-secret'})
    assert store.path.read_bytes() == before
    if change == 'missing_key':
        assert not (tmp_path / 'session_secret').exists()


def test_failed_migration_preserves_legacy_file_and_cleans_temporary_output(tmp_path):
    store = ProfileStore(str(tmp_path))
    store.path.write_text('[{"name":"Lab","api_key":"legacy-secret"}]')
    original = store.path.read_bytes()
    with patch('twn_toolkit.profiles.os.replace', side_effect=OSError('disk failure')):
        with pytest.raises(OSError, match='disk failure'):
            store.protect_existing()
    assert store.path.read_bytes() == original
    assert not list(tmp_path.glob('.profiles-*.json'))


def test_cli_migration_preserves_values_and_is_repeatable(tmp_path):
    for cls, field in SECRET_STORES[:5]:
        store = cls(str(tmp_path))
        store.path.write_text(json.dumps([{'name': 'Lab', field: 'legacy-secret'}]))
    for _ in range(2):
        result = subprocess.run([sys.executable, '-m', 'twn_toolkit.profile_secrets', '--instance', str(tmp_path)],
                                capture_output=True, text=True, timeout=20, check=True)
        assert 'legacy-secret' not in result.stdout + result.stderr
    for cls, field in SECRET_STORES[:5]:
        store = cls(str(tmp_path))
        assert 'legacy-secret' not in store.path.read_text()
        assert store.get('Lab')[field] == 'legacy-secret'


def test_portable_store_transfer_reencrypts_for_destination_key(tmp_path):
    source = ProfileStore(str(tmp_path / 'source'))
    destination = ProfileStore(str(tmp_path / 'destination'))
    source.upsert({'name': 'Lab', 'api_key': 'portable-secret'})
    destination.replace_all(source.all())
    assert source.path.read_bytes() != destination.path.read_bytes()
    assert source.get('Lab') == destination.get('Lab')
    assert 'portable-secret' not in destination.path.read_text()


def test_environment_key_override_is_required_consistently(tmp_path, monkeypatch):
    monkeypatch.setenv('TWN_TOOLKIT_SECRET_KEY', 'fixture-override')
    store = ProfileStore(str(tmp_path))
    store.upsert({'name': 'Lab', 'api_key': 'secret'})
    assert store.get('Lab')['api_key'] == 'secret'
    assert not (tmp_path / 'session_secret').exists()
    monkeypatch.delenv('TWN_TOOLKIT_SECRET_KEY')
    with pytest.raises(ValueError, match='could not be decrypted'):
        store.get('Lab')


def test_configuration_backup_round_trip_uses_portable_secrets(tmp_path):
    from twn_toolkit.profile_backup import (
        build_backup_catalog, selected_backup_items, build_profile_backup,
        encrypt_backup, decrypt_backup, import_backup_items,
    )
    groups = {'fortigate_profiles', 'fortiauthenticator_profiles', 'radius_server_profiles', 'radius_credential_profiles', 'snmp_credential_profiles'}
    fields = {'fortigate_profiles': 'api_key', 'fortiauthenticator_profiles': 'password', 'radius_server_profiles': 'secret', 'radius_credential_profiles': 'password', 'snmp_credential_profiles': 'community'}
    source = selected_backup_items(build_backup_catalog(str(tmp_path / 'source')), groups)
    for item in source:
        field = fields[item['id']]
        item['store'].upsert({'name': 'Lab', field: 'portable-secret'})
    backup = build_profile_backup(source)
    protected_export = encrypt_backup(json.dumps(backup).encode(), 'export-password')
    assert 'portable-secret' not in json.dumps(protected_export)
    restored = decrypt_backup(protected_export, 'export-password')
    destination = selected_backup_items(build_backup_catalog(str(tmp_path / 'destination')), groups)
    import_backup_items(restored['items'], destination, 'replace')
    for item in destination:
        field = fields[item['id']]
        assert item['store'].get('Lab')[field] == 'portable-secret'
        assert b'portable-secret' not in storage_path(item['store']).read_bytes()


def test_snmp_ciphertext_cannot_be_swapped_between_auth_and_privacy(tmp_path):
    store = SNMPCredentialProfileStore(str(tmp_path))
    store.upsert({'name': 'Lab', 'auth_key': 'authentication-secret', 'priv_key': 'privacy-secret'})
    with sqlite3.connect(store.mso_store().path) as db:
        raw = json.loads(db.execute("SELECT payload FROM mso_objects WHERE kind='snmp.credentials'").fetchone()[0])
        raw['auth_key'], raw['priv_key'] = raw['priv_key'], raw['auth_key']
        db.execute("UPDATE mso_objects SET payload=? WHERE kind='snmp.credentials'", (json.dumps(raw),))
    with pytest.raises(ValueError, match='could not be decrypted'):
        store.get('Lab')


@pytest.mark.parametrize('kind,field', [('servers', 'secret'), ('credentials', 'password')])
def test_radius_rename_and_legacy_migration_preserve_secret(tmp_path, kind, field):
    store = RadiusProfileStore(str(tmp_path), kind)
    store.path.write_text(json.dumps([{'name': 'Old', field: 'legacy-secret'}]))
    old = store.get('Old')
    store.upsert({**old, 'name': 'New'}, original_name='Old')
    assert store.get('Old') is None
    assert store.get('New')[field] == 'legacy-secret'
    assert 'legacy-secret' not in store.path.read_text()


def test_radius_attributes_remain_plain_and_do_not_create_key(tmp_path):
    store = RadiusProfileStore(str(tmp_path), 'attributes')
    profile = {'name': 'NAS', 'source': 'NAS-Identifier = lab'}
    store.upsert(profile)
    import sqlite3
    with sqlite3.connect(store.mso_store().path) as db:
        raw = db.execute('SELECT payload FROM mso_objects WHERE kind=?', ('radius.attributes',)).fetchone()[0]
    assert json.loads(raw) == profile
    assert not (tmp_path / 'session_secret').exists()
