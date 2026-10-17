"""#140400: the batch ``clarify`` request a local viewer gets is answered with ``clarify.lock``.

Ink's batch panel and Desktop's batch card lock each answer with ``clarify.lock {request_id,
question_id, answer}``. The owner's ``AuthorityConnection.dispatch`` had no such verb (``-32601
unknown method``), so every answer was refused and the turn sat out ``clarify_timeout``. Driven
through the real dispatcher against a real ``ask_clarify_batch`` wait.
"""
import asyncio
import os
from pathlib import Path
import subprocess
import sys
import threading
from types import SimpleNamespace

import pytest

from gateway.config import Platform
from tests.gateway.test_surface_admission import _authority

QUESTIONS = [{'qid': 'q0', 'question': 'colour?', 'choices': ['red', 'blue'], 'multi_select': False},
             {'qid': 'q1', 'question': 'size?', 'choices': None, 'multi_select': False}]


class _Peer:
    def __init__(self):
        self.frames = []

    def write(self, frame):
        self.frames.append(frame)
        return True

    def close(self):
        pass


async def _wait_for(predicate, timeout=5.0):
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while not predicate():
        assert loop.time() < deadline
        await asyncio.sleep(0.01)


def _start_batch(authority):
    from gateway.session_clarify_batch import ask_clarify_batch
    peer = _Peer()
    authority.sessions['s'].event_stream.fanout.attach(peer)
    turn = SimpleNamespace(_approval_owner=(authority, 's', 1), _ctx=SimpleNamespace(
        source=SimpleNamespace(platform=Platform.LOCAL), agent_holder=[SimpleNamespace(_interrupt_requested=False)]))
    out = {}
    worker = threading.Thread(target=lambda: out.update(ask_clarify_batch(turn, QUESTIONS)), daemon=True)
    worker.start()
    return peer, worker, out


async def _lock(connection, rid, qid, answer, n):
    return await connection.dispatch({'id': n, 'method': 'clarify.lock', 'params': {
        'request_id': rid, 'question_id': qid, 'answer': answer}})


@pytest.mark.asyncio
async def test_clarify_lock_answers_the_owner_batch_request(tmp_path, monkeypatch):
    from gateway.session_controls import AuthorityConnection

    async def answer(event):
        return 'ok'
    authority = await _authority(tmp_path, monkeypatch, answer)
    connection = AuthorityConnection(authority, object(), {'user_id': 'owner'})
    try:
        await connection.dispatch({'id': 1, 'method': 'session.resume', 'params': {'session_id': 's'}})
        peer, worker, out = _start_batch(authority)
        await _wait_for(lambda: any(f.get('method') == 'clarify' for f in peer.frames))
        rid = next(f['id'] for f in peer.frames if f.get('method') == 'clarify')

        first = await _lock(connection, rid, 'q0', 'blue', 2)
        assert first.get('result') == {'status': 'ok', 'remaining': ['q1']}, first
        # Revisit before the last lock: the newer answer wins.
        assert (await _lock(connection, rid, 'q0', 'red', 3))['result']['remaining'] == ['q1']
        unknown = await _lock(connection, rid, 'zz', 'x', 4)
        assert unknown['error']['message'] == 'invalid_params', unknown
        last = await _lock(connection, rid, 'q1', None, 5)
        assert last.get('result') == {'status': 'ok', 'remaining': []}, last
        await asyncio.to_thread(worker.join, 5)
        assert out == {'answers': {'q0': 'red', 'q1': None}, 'outcome': 'submitted'}
        late = await _lock(connection, rid, 'q1', 'late', 6)
        assert late.get('result') == {'status': 'expired'}, late
    finally:
        await connection.close()


@pytest.mark.asyncio
async def test_a_viewer_without_the_session_cannot_lock_its_answers(tmp_path, monkeypatch):
    from gateway.session_controls import AuthorityConnection
    from gateway.session_sudo_prompt import resolve

    async def answer(event):
        return 'ok'
    authority = await _authority(tmp_path, monkeypatch, answer)
    outsider = AuthorityConnection(authority, object(), {'user_id': 'someone-else'})
    try:
        peer, worker, out = _start_batch(authority)
        await _wait_for(lambda: any(f.get('method') == 'clarify' for f in peer.frames))
        rid = next(f['id'] for f in peer.frames if f.get('method') == 'clarify')
        refused = await _lock(outsider, rid, 'q0', 'red', 2)
        assert refused.get('result') == {'status': 'expired'}, refused
        resolve({'jsonrpc': '2.0', 'id': rid, 'result': {}})  # the session's own viewer cancels
        await asyncio.to_thread(worker.join, 5)
        assert out['answers'] == {}
    finally:
        await outsider.close()


def test_cli_turn_batch_answered_by_clarify_lock_from_a_second_viewer_end_to_end(tmp_path):
    """Real gateway process path: the locked answers reach the real model's tool result."""
    home, state = tmp_path / 'home', tmp_path / 'state'
    home.mkdir()
    state.mkdir()
    repo = Path(__file__).resolve().parents[2]
    env = {key: os.environ[key] for key in ('PATH', 'LANG', 'TZ') if key in os.environ}
    env.update(HOME=str(home), USERPROFILE=str(home), HERMES_HOME=str(state), PYTHONPATH=str(repo))
    result = subprocess.run(
        [sys.executable, str(Path(__file__).parent / 'fixtures' / 'authority_clarify_lock_peer.py')],
        cwd=tmp_path, env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=90, check=False)
    assert result.returncode == 0, result.stdout + result.stderr
    assert (state / 'lock-passed').read_text() == 'both locked answers reached the real model'
