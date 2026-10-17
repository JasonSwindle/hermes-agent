"""CFG-10 (#140290): a frozen config-secret reference is bound to the secrets it carries and the endpoints
they authenticate, not to every byte of the policy.

A reference stamped by an older gateway hashes the policy fields it knew then; once a later release added a
field to the policy (``skills_prompt``, ``kanban_json``, ``safe_mode``/``ignore_user_config``) that hash no
longer matched, and every turn of the session failed with a bare ``launch_credentials_unavailable``. ``/model``,
the one edit that would re-stamp it, recovered the old secrets first and failed the same way. Real
SessionStore/SessionAuthority, a real config.yaml, and a receipt holding the reference an older gateway wrote.
"""
import hashlib
import json
from dataclasses import asdict, replace
from types import SimpleNamespace

import pytest

from tests.gateway.test_session_resume_config_refresh import _call, _connect, _owner_authority

CONFIG = ('model: {default: m1, provider: custom, base_url: "http://127.0.0.1:9/v1", api_key: route-token}\n'
          'agent: {reasoning_effort: high}\nplatform_toolsets: {cli: [terminal]}\nterminal: {backend: local}\n'
          'mcp_servers: {docs: {command: docs-mcp, env: {DOCS_TOKEN: mcp-token}}}\n')
# The policy fields an older gateway's reference did not hash (they did not exist when it was stamped).
_LATER_FIELDS = ('kanban_json', 'safe_mode', 'ignore_user_config', 'skills_prompt', 'editor_mcp_json',
                 'coding_posture', 'client_env_json', 'client_env_remote', 'client_env_rules_json')


def _home(monkeypatch):
    from gateway import run
    from hermes_constants import get_hermes_home
    home = get_hermes_home()
    home.mkdir(parents=True, exist_ok=True)
    (home / 'config.yaml').write_text(CONFIG)
    monkeypatch.setattr(run, '_hermes_home', home)
    return home


def _older_gateway_reference(policy):
    """The reference the first release of frozen config secrets wrote for *policy*: the whole-policy hash
    over the fields it had, no ``bound`` endpoints."""
    from gateway.session_policy_credentials import PREFIX
    source = json.loads(policy.config_secret_ref[len(PREFIX):])
    data = {k: v for k, v in asdict(policy).items()
            if k not in ('credential_ref', 'config_secret_ref', *_LATER_FIELDS)}
    source['policy'] = hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()
    source.pop('bound', None)
    return PREFIX + json.dumps(source, sort_keys=True)


def _store_reference(store, sid, ref):
    from hermes_state_local import POLICY_PREFIX
    def write(conn):
        saved = json.loads(conn.execute('SELECT value FROM state_meta WHERE key=?',
                                        (POLICY_PREFIX + sid,)).fetchone()[0])
        saved['policy']['config_secret_ref'] = ref
        conn.execute('UPDATE state_meta SET value=? WHERE key=?', (json.dumps(saved), POLICY_PREFIX + sid))
    store._db._execute_write(write)


def _stored_policy(store, sid):
    from gateway.session_policy import restore_policy
    from hermes_state_local import local_receipt
    return restore_policy(local_receipt(store._db, sid)['policy'])


async def _older_session(tmp_path, monkeypatch):
    """A session whose receipt an older gateway stamped, adopted by a restarted current owner."""
    home = _home(monkeypatch)
    store, first = await _owner_authority(home, 'first')
    owner = _connect(first)
    sid = (await _call(owner, 'session.create', request_id='s', source='cli', cwd=str(tmp_path)))['session_id']
    await owner.close()
    _store_reference(store, sid, _older_gateway_reference(_stored_policy(store, sid)))
    store.close_all_db_handles()
    store, cold = await _owner_authority(home, 'cold')
    return home, store, cold, sid


@pytest.mark.asyncio
async def test_a_reference_stamped_by_an_older_gateway_still_runs_its_session(tmp_path, monkeypatch):
    home, store, cold, sid = await _older_session(tmp_path, monkeypatch)
    try:
        config = _stored_policy(store, sid).config(cold)
        assert config['model']['api_key'] == 'route-token'
        assert config['mcp_servers']['docs']['env'] == {'DOCS_TOKEN': 'mcp-token'}
        # Its values are still gated by their fingerprints: the route key rotated is refused by name.
        (home / 'config.yaml').write_text(CONFIG.replace('route-token', 'rotated-token'))
        fresh = SimpleNamespace(db=store._db, profile_id=cold.profile_id)
        from hermes_state_runtime import RuntimeStoreError
        with pytest.raises(RuntimeStoreError, match='launch_credentials_unavailable') as refused:
            _stored_policy(store, sid).config(fresh)
        assert refused.value.field == 'model.api_key'
    finally:
        store.close_all_db_handles()


@pytest.mark.asyncio
async def test_model_re_stamps_a_reference_an_older_gateway_wrote(tmp_path, monkeypatch):
    from hermes_cli import model_switch
    from gateway.session_policy_credentials import PREFIX, policy_identity
    monkeypatch.setattr(model_switch, 'switch_model', lambda **k: model_switch.ModelSwitchResult(
        success=True, new_model='m2', target_provider='custom', base_url='http://127.0.0.1:9/v1'))
    _home_dir, store, cold, sid = await _older_session(tmp_path, monkeypatch)
    viewer = _connect(cold)
    try:
        snap = store._db.get_session(sid)
        reply = await viewer.dispatch({'id': 1, 'method': 'session.mutate', 'params': {
            'session_id': sid, 'request_id': 'switch', 'operation': 'model', 'payload': {'model': 'm2'},
            'expected_revision': snap['runtime_revision'], 'expected_generation': snap['runtime_generation']}})
        assert 'result' in reply, reply
        switched = _stored_policy(store, sid)
        assert switched.model == 'm2'
        source = json.loads(switched.config_secret_ref[len(PREFIX):])
        assert source['policy'] == policy_identity(switched) and 'bound' in source
        # The next turn's read, on an owner with nothing cached, recovers the same secrets.
        restarted = SimpleNamespace(db=store._db, profile_id=cold.profile_id)
        assert switched.config(restarted)['model']['api_key'] == 'route-token'
    finally:
        await viewer.close()
        store.close_all_db_handles()


@pytest.mark.asyncio
@pytest.mark.parametrize('edit', ['base_url', 'reasoning', 'mcp_list'])
async def test_a_non_secret_profile_edit_keeps_the_session_and_its_model_switch(tmp_path, monkeypatch, edit):
    """The profile edit the issue names, then a restart, a resume (its settings refresh re-stamps the
    reference) and the session's next turn read and ``/model``."""
    from hermes_cli import model_switch
    monkeypatch.setattr(model_switch, 'switch_model', lambda **k: model_switch.ModelSwitchResult(
        success=True, new_model='m2', target_provider='custom', base_url='http://127.0.0.1:9/v1'))
    home = _home(monkeypatch)
    store, first = await _owner_authority(home, 'first')
    owner = _connect(first)
    sid = (await _call(owner, 'session.create', request_id='s', source='cli', cwd=str(tmp_path)))['session_id']
    await owner.close()
    store.close_all_db_handles()
    (home / 'config.yaml').write_text({
        'base_url': CONFIG.replace('127.0.0.1:9', '127.0.0.1:10'),
        'reasoning': CONFIG.replace('reasoning_effort: high', 'reasoning_effort: low'),
        'mcp_list': CONFIG.replace('}}}\n', '}}, extra: {command: extra-mcp}}\n')}[edit])
    store, cold = await _owner_authority(home, 'cold')
    viewer = _connect(cold)
    try:
        resumed = await _call(viewer, 'session.resume', session_id=sid)
        assert _stored_policy(store, sid).config(cold)['model']['api_key'] == 'route-token'
        reply = await viewer.dispatch({'id': 1, 'method': 'session.mutate', 'params': {
            'session_id': sid, 'request_id': 'switch', 'operation': 'model', 'payload': {'model': 'm2'},
            'expected_revision': resumed['revision'], 'expected_generation': resumed['execution_generation']}})
        assert 'result' in reply, reply
        assert _stored_policy(store, sid).config(cold)['model']['api_key'] == 'route-token'
    finally:
        await viewer.close()
        store.close_all_db_handles()


def _bound_policy(tmp_path, monkeypatch):
    from gateway.session_policy import bind_launch_key, build_policy
    home = tmp_path / 'profile'
    home.mkdir()
    monkeypatch.setenv('HERMES_HOME', str(home))
    cfg = {'model': {'provider': 'custom', 'api_key': 'route-token', 'base_url': 'http://127.0.0.1:1234/v1'},
           'mcp_servers': {'docs': {'command': 'docs-mcp', 'env': {'DOCS_TOKEN': 'mcp-token'}}}}
    (home / 'config.yaml').write_text(json.dumps(cfg))

    def owner(path=home, profile='owned'):  # a fresh authority per read, like a restarted owner
        return SimpleNamespace(db=SimpleNamespace(db_path=path / 'state.db'), profile_id=profile,
                               instance_id='new', epoch=2)
    private = {}
    policy = build_policy({'cwd': str(home), 'model': 'frozen'}, cfg, private_secrets=private)
    return home, cfg, owner, bind_launch_key(owner(), 'session', policy, None, config_secrets=private)


def test_a_non_secret_policy_change_keeps_the_reference(tmp_path, monkeypatch):
    """Fields no secret depends on (model name, reasoning, toolsets, a policy field a later release adds)
    move without invalidating the reference."""
    _home_dir, _cfg, owner, policy = _bound_policy(tmp_path, monkeypatch)
    config = json.loads(policy.config_json)
    config.setdefault('agent', {})['reasoning_effort'] = 'low'
    config['mcp_servers']['extra'] = {'command': 'extra-mcp'}
    moved = replace(policy, model='other', toolsets=('web',), skills_prompt='later field',
                    config_json=json.dumps(config))
    recovered = moved.config(owner())
    assert recovered['model']['api_key'] == 'route-token'
    assert recovered['mcp_servers']['docs']['env'] == {'DOCS_TOKEN': 'mcp-token'}


@pytest.mark.parametrize('scope', ['home', 'profile'])
def test_another_home_or_profile_is_refused_by_name(tmp_path, monkeypatch, scope):
    from hermes_state_runtime import RuntimeStoreError
    _home_dir, _cfg, owner, policy = _bound_policy(tmp_path, monkeypatch)
    wrong = owner(path=tmp_path) if scope == 'home' else owner(profile='other')
    with pytest.raises(RuntimeStoreError, match='launch_credentials_unavailable') as refused:
        policy.config(wrong)
    assert refused.value.field == scope and refused.value.detail


def test_a_revoked_route_secret_is_still_refused(tmp_path, monkeypatch):
    from hermes_state_runtime import RuntimeStoreError
    home, cfg, owner, policy = _bound_policy(tmp_path, monkeypatch)
    del cfg['model']['api_key']
    (home / 'config.yaml').write_text(json.dumps(cfg))
    with pytest.raises(RuntimeStoreError, match='launch_credentials_unavailable') as refused:
        policy.config(owner())
    assert refused.value.field == 'model.api_key'


@pytest.mark.parametrize('moved', ['model', 'mcp'])
def test_a_secret_paired_with_a_moved_endpoint_is_refused_by_name(tmp_path, monkeypatch, moved):
    """The scoped check still binds each secret to the endpoint it authenticates in the frozen policy: a
    policy rewrite that repoints it without re-binding never sends the key to the new endpoint."""
    from hermes_state_runtime import RuntimeStoreError
    _home_dir, _cfg, owner, policy = _bound_policy(tmp_path, monkeypatch)
    config = json.loads(policy.config_json)
    if moved == 'model':
        config['model']['base_url'] = 'http://attacker.invalid/v1'
        field = 'model.api_key'
    else:
        config['mcp_servers']['docs']['command'] = 'other-mcp'
        field = 'mcp_servers.docs.env'
    with pytest.raises(RuntimeStoreError, match='launch_credentials_unavailable') as refused:
        replace(policy, config_json=json.dumps(config)).config(owner())
    assert refused.value.field == field and 'endpoint' in refused.value.detail
