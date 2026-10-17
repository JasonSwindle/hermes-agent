"""``clarify.lock`` on the session owner (#140400).

The owner sends a local viewer's clarify batch as one ``clarify`` server request
(``gateway/session_clarify_batch.py``). Ink's batch panel and Desktop's batch card answer it one
question at a time with ``clarify.lock {request_id, question_id, answer}`` (``ClarifyLockParams`` /
``ClarifyLockResult``), as they did against main's sidecar; the owner had no such verb, so every
answer was refused as an unknown method and the turn waited out ``clarify_timeout``. Only a viewer
attached to the request's session with ``session:respond`` may lock its answers.
"""
import json

from gateway.session_contract import SessionRef
from hermes_state_runtime import RuntimeStoreError

_FIELDS = frozenset({'request_id', 'question_id', 'answer', 'profile'})


async def clarify_lock(connection, ref, params):
    from gateway.session_sudo_prompt import lock_answer
    request_id, question_id = params.get('request_id'), params.get('question_id')
    # ``profile`` naming another served profile was routed to its owner by ``dispatch``.
    if (set(params) - _FIELDS or not isinstance(request_id, str) or not request_id
            or not isinstance(question_id, str) or not question_id
            or not isinstance(params.get('profile', ''), (str, type(None)))):
        raise RuntimeStoreError('invalid_params')
    answer = params.get('answer', '')
    if answer is not None and not isinstance(answer, str):
        answer = json.dumps(answer, ensure_ascii=False)
    authority, actor = connection.authority, connection.actor

    def entitled(session_id):
        try:
            authority.authorize(actor, SessionRef(authority.profile_id, session_id), 'session:respond')
        except RuntimeStoreError:
            return False
        live = authority.sessions.get(session_id)
        return live is not None and actor in live.subscribers.values()
    try:
        remaining = lock_answer(request_id, question_id, answer, session_ok=entitled)
    except ValueError:
        raise RuntimeStoreError('invalid_params') from None
    if remaining is None:
        # The wait already ended (timeout / cancel) while the card was still visible: not an error.
        return {'status': 'expired'}
    return {'status': 'ok', 'remaining': remaining}
