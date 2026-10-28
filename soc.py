"""Deterministic SOC summaries over persisted events, never claims compromise."""
from collections import Counter

def summarize(events):
    suspicious = [e for e in events if e['decision'] != 'ALLOW']
    endpoints = Counter(e['endpoint'] for e in suspicious)
    patterns = Counter(e['category'] for e in suspicious)
    repeated = Counter(e['actor'] for e in suspicious)
    result = dict(total=len(events), attacks=len(suspicious), allowed=sum(e['decision']=='ALLOW' for e in events),
        review=sum(e['decision']=='REVIEW' for e in events),
        blocked=sum(e['decision']=='BLOCK' for e in events), high=sum(e['risk']=='high' for e in events),
        endpoints=endpoints, categories=patterns, risks=Counter(e['risk'] for e in events),
        trends=Counter(e['timestamp'][:10] for e in suspicious),
        repeated={k:v for k,v in repeated.items() if v >= 3},
        recent=[e for e in events if e['risk']=='high'][:20])
    result['modes'] = Counter(e.get('mode') or 'historical-unspecified' for e in events)
    result['errors'] = Counter(e.get('model_error') for e in events if e.get('model_error'))
    result['summary'] = (f"Observed {len(suspicious)} suspicious requests among {len(events)} analyzed form submissions. "
        f"{result['blocked']} were blocked; {sum(e['decision']=='REVIEW' for e in events)} were allowed with review flags. "
        f"Targeted endpoints: {dict(endpoints)}. Matched categories: {dict(patterns)}. "
        f"{len(result['repeated'])} browser sessions had at least three suspicious submissions. "
        + ('Investigate recent high-risk events and repeated activity; verify application and database audit logs. ' if suspicious else 'No suspicious activity in this reporting window. ')
        + 'These detections do not establish successful compromise.')
    return result
