"""Validate DNS-over-HTTPS status and answer ownership before reading records."""
from brand_registry import normalize_hostname


def dns_answers(payload: object, query: str, rrtype: int) -> list[dict]:
    if not isinstance(payload, dict) or type(payload.get('Status')) is not int:
        raise ValueError('Invalid DoH DNS status')
    status = payload['Status']
    if status not in (0, 3):
        raise ValueError(f'DNS query failed with RCODE {status}')
    if 'TC' in payload and type(payload['TC']) is not bool:
        raise ValueError('Invalid DNS truncation flag')
    if payload.get('TC'):
        raise ValueError('Truncated DNS response')
    query = normalize_hostname(query)
    if not query:
        raise ValueError('Invalid DNS question')
    questions = payload.get('Question', [])
    if not isinstance(questions, list) or any(not isinstance(q, dict) or
            normalize_hostname(q.get('name', '')) != query or q.get('type') != rrtype for q in questions):
        raise ValueError('DNS question differs from request')
    answers = payload.get('Answer', [])
    if not isinstance(answers, list) or len(answers) > 512 or any(not isinstance(a, dict) for a in answers):
        raise ValueError('Invalid DNS answers')
    if status == 3:
        if any(a.get('type') == rrtype for a in answers):
            raise ValueError('NXDOMAIN response contains positive requested records')
        return []
    names = {query}
    for _ in range(16):
        expanded = set(names)
        for answer in answers:
            if answer.get('type') == 5 and normalize_hostname(answer.get('name', '')) in names:
                target = normalize_hostname(answer.get('data', ''))
                if not target:
                    raise ValueError('Invalid DNS CNAME')
                expanded.add(target)
        if expanded == names:
            break
        names = expanded
    else:
        raise ValueError('DNS alias chain exceeds budget')
    result = []
    for answer in answers:
        if answer.get('type') == rrtype:
            if normalize_hostname(answer.get('name', '')) not in names or not isinstance(answer.get('data'), str):
                raise ValueError('DNS answer differs from requested name or alias')
            result.append(answer)
    return result
