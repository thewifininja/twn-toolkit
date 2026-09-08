"""Finite case exports using a consistent database read snapshot."""
from __future__ import annotations

from contextlib import contextmanager
import json
import sys

from .diagnostic_artifacts import artifact_directory, PrivateArtifactStore
from .datastore import DatastoreError
from .investigations import InvestigationStore
from .case_export_source import CaseExportLimitError, selected_case_snapshot
from .investigation_reporting import case_report_contents
from .investigation_exports import build_case_report_pdf, build_case_package, case_package_filename, case_report_filename
from .investigation_portability import build_portable_case_archive, portable_case_filename

TOOL = 'case_export'
KINDS = {'pdf': 'PDF report', 'package': 'Case package', 'portable': 'Portable case'}


class ExportCaseStore(InvestigationStore):
    """A worker-local reader; nested store reads share one SQLite snapshot."""
    snapshot_connection = None

    @contextmanager
    def _connect(self):
        if self.snapshot_connection is not None:
            yield self.snapshot_connection
        else:
            with super()._connect() as connection:
                yield connection

    def snapshot(self, case_id, user_id, kind, input_limit):
        if kind not in KINDS:
            raise CaseExportLimitError('Unknown case export format.')
        with selected_case_snapshot(self.path, case_id, user_id, kind, input_limit) as (connection, counts, names):
            self.snapshot_connection = connection
            try:
                if kind == 'portable':
                    result = self.portable_case_for_user(case_id, user_id)
                else:
                    investigation = self.get_for_user(case_id, user_id)
                    participants = self.participants_for_user(case_id, user_id)
                    events = self.events_for_user(case_id, user_id, report_only=True)
                    artifacts = self.artifacts_for_user(case_id, user_id, report_only=True)
                    names.update(str(item.get('username', '')) for item in (investigation.get('source_operators') or participants))
                    investigation['participants'] = participants
                    investigation['operator_names'] = ', '.join(sorted(name for name in names if name))
                    result = {'investigation': investigation, 'events': events, 'artifacts': artifacts}
                result['investigation']['event_count'] = counts['events']
                result['investigation']['artifact_count'] = counts['artifacts']
                return result
            finally:
                self.snapshot_connection = None


class ReservedExportFile:
    """Sequential export output shares physical reservations with every upload."""
    def __init__(self, artifacts, job_id):
        try:
            self.upload = artifacts.begin_upload(job_id, 'export.bin')
        except DatastoreError as exc:
            raise CaseExportLimitError('Case export could not reserve private storage.') from exc

    def write(self, value):
        try:
            return self.upload.write(value)
        except DatastoreError as exc:
            raise CaseExportLimitError('Case export storage limit: '+str(exc).replace('Uploads', 'Exports').replace('upload', 'export')) from exc

    def commit(self):
        try:
            return self.upload.commit()
        except DatastoreError as exc:
            raise CaseExportLimitError('Case export publication failed: '+str(exc)) from exc

    def __getattr__(self, name):
        return getattr(self.upload, name)


def execute_case_export(store, job, config):
    directory = artifact_directory(store, job['id'], TOOL)
    output = None
    try:
        kind = config['kind']
        if kind not in KINDS:
            raise CaseExportLimitError('Unknown case export format.')
        cases = ExportCaseStore(str(store.instance))
        snapshot = cases.snapshot(config['investigation_id'], job['user_id'], kind, config['input_bytes'])
        investigation = snapshot['investigation']
        report = None
        if kind != 'portable':
            report = case_report_contents(snapshot['events'], snapshot['artifacts'])
            cells = sum(sum(len(row) for row in (presentation.get('detail') or {}).get('rows', []))
                        for presentation in report['event_presentations'].values())
            if cells > config['pdf_cells']:
                raise CaseExportLimitError('The report exceeds the configured PDF detail-cell limit. Reduce the included diagnostics or increase the limit in Settings → Operations. Portable cases retain the original data.')
        artifacts = PrivateArtifactStore(store.instance, TOOL, config['artifact_bytes'])
        directory.mkdir(mode=0o700)
        output = ReservedExportFile(artifacts, job['id'])
        if kind == 'pdf':
            output.write(build_case_report_pdf(investigation, report))
            filename, mimetype = case_report_filename(investigation), 'application/pdf'
        elif kind == 'package':
            build_case_package(store=cases, investigation=investigation, report=report, archive=output)
            filename, mimetype = case_package_filename(investigation), 'application/zip'
        else:
            build_portable_case_archive(store=cases, archive=output, **snapshot)
            filename, mimetype = portable_case_filename(investigation), 'application/vnd.twn-toolkit.case+zip'
        output.commit()
        summary = {'filename':filename, 'mimetype':mimetype, 'byte_count':(directory/'export.bin').stat().st_size,
                   'event_count':len(snapshot['events']), 'artifact_count':len(snapshot['artifacts'])}
        if store.finish(job['id'], job['token'], [], summary):
            record_case_export_outcome(store, job, 'succeeded', config=config)
    except Exception as exc:
        # Export inputs contain arbitrary case data; do not echo library exceptions
        # that might include retained evidence or credentials into unencrypted errors.
        error = str(exc) if isinstance(exc, CaseExportLimitError) else 'Case export failed ('+type(exc).__name__+'). Check case access and evidence integrity.'
        current = store.owned(job['id'], job['token'])
        state = 'cancelled' if current and current['state']=='cancel_requested' else 'failed'
        if store.abort(job['id'], job['token'], state, error):
            record_case_export_outcome(store, job, state, config=config)
    finally:
        if output is not None:
            output.close()


def record_case_export_outcome(store, job, state, *, config=None):
    from .audit import AuditStore
    try:
        if config is None:
            config = job['config']
            if isinstance(config, str):
                config = json.loads(store.cipher.open(config, job['id']+':diagnostic-config'))
        AuditStore(str(store.instance)).record(user_id=job['user_id'], username=config['username'],
            method='WORKER', endpoint='case_export_job', path='/investigations/'+config['investigation_id']+'/exports',
            status_code=200, category='Investigations', action='investigation.export_'+state,
            summary=KINDS[config['kind']]+' '+state+'.', resource_id=config['investigation_id'],
            details={'operation id':job['id'], 'format':config['kind'], 'outcome':state})
    except Exception as exc:
        print('Case export audit recording failed: '+type(exc).__name__, file=sys.stderr)
