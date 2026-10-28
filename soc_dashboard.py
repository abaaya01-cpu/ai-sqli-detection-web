"""Read-only SOC views. Detection, writes, authorization policy and schema stay external."""
import json
import math
import re
from collections import Counter
from datetime import date, datetime, timezone
from functools import wraps
from urllib.parse import urlencode
from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, session, url_for
from database import is_single_admin, query
from soc import summarize

soc_pages = Blueprint('soc_pages', __name__, url_prefix='/admin')
COLUMNS = ('id','timestamp','endpoint','score','risk','decision','category','indicators',
           'model_probability','model_status','mode','decision_source','rule_score','model_error','actor')
WINDOW = 10000
FALLBACK_SQL = "(LOWER(COALESCE(model_error,model_status,'')) LIKE '%fallback%' OR LOWER(COALESCE(model_error,model_status,'')) LIKE '%failed%')"
SOURCE_SQL = f"""CASE WHEN {FALLBACK_SQL} THEN 'fallback'
    WHEN LOWER(decision_source) IN ('rules','lstm','input-limit') THEN LOWER(decision_source)
    WHEN LOWER(mode) IN ('hybrid','lstm','rules-only') THEN CASE LOWER(mode) WHEN 'rules-only' THEN 'rules' ELSE LOWER(mode) END
    ELSE 'unspecified' END"""
SOURCE_NAMES = {'lstm':'LSTM','rules':'Rules','hybrid':'Hybrid','fallback':'Fallback',
                'input-limit':'Input limit','unspecified':'Unspecified'}


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if 'user_id' not in session:
            return redirect('/login')
        if not is_single_admin(session['user_id']):
            flash('Access Denied!', 'danger')
            return redirect('/dashboard')
        return view(*args, **kwargs)
    return wrapped


@soc_pages.before_request
def authorize():
    # Exactly the same current role + reserved-slot check as the original /admin.
    return admin_required(lambda:None)()


def safe_number(value):
    try:
        n = float(value)
        return n if math.isfinite(n) else None
    except (ValueError, TypeError):
        return None


def mode_name(mode):
    return {'hybrid':'Hybrid','lstm':'LSTM','rules-only':'Rules only'}.get(mode,'Not recorded')


def event_view(row):
    event = dict(zip(COLUMNS, row))
    # Actor correlation is used internally by the existing summary only.
    event.pop('actor',None)
    # Never display actor/session IDs, payloads, accounts or raw errors.
    event['timestamp'] = str(event['timestamp'] or '')[:64]
    error = str(event['model_error'] or event['model_status'] or '').lower()
    fallback = 'fallback' in error or 'failed' in error
    source = str(event['decision_source'] or '').lower()
    if fallback:
        source = 'fallback'
    elif source not in ('rules','lstm','input-limit'):
        source = {'hybrid':'hybrid','lstm':'lstm','rules-only':'rules'}.get(event['mode'],'unspecified')
    event['source'] = source
    event['source_label'] = SOURCE_NAMES[source]
    event['mode_label'] = mode_name(event['mode'])
    event['decision'] = event['decision'] if event['decision'] in ('ALLOW','BLOCK','REVIEW') else 'UNSPECIFIED'
    event['risk'] = event['risk'] if event['risk'] in ('low','medium','high') else 'unspecified'
    event['endpoint'] = str(event['endpoint'] or 'Not recorded')[:255]
    event['category'] = str(event['category'] or 'Not recorded')[:100]
    for key in ('score','model_probability','rule_score'):
        event[key] = safe_number(event[key])
    try:
        items = json.loads(event['indicators'] or '[]')
        event['evidence'] = [str(x)[:100] for x in items[:12] if isinstance(x,(str,int,float))] if isinstance(items,list) else []
    except (TypeError, ValueError):
        event['evidence'] = []
    if fallback:
        event['status_label'] = 'Model failure or fallback recorded. Inspect application diagnostics locally.'
    elif event['model_probability'] is not None:
        event['status_label'] = 'Model output recorded for this event.'
    else:
        event['status_label'] = 'No model output recorded for this event.'
    event['fallback'] = fallback
    # Raw diagnostic text can include private paths or configuration from legacy
    # integrations. Only the safe status above is sent to the templates.
    event.pop('model_error',None); event.pop('model_status',None)
    return event


def read_window():
    rows = query('SELECT '+','.join(COLUMNS)+' FROM security_events ORDER BY id DESC LIMIT %s',(WINDOW,),True)
    events = [event_view(row) for row in rows]
    internal = [dict(zip(COLUMNS,row)) for row in rows]
    for item in internal:
        item['timestamp'] = str(item['timestamp'] or '')
        item['actor'] = item['actor'] or f'missing-actor-event-{item["id"]}'
    return events, summarize(internal)


def public_status():
    status = current_app.extensions['sqli_detector'].status()
    artifact = str(status.get('artifact') or 'none')
    artifact = artifact if re.fullmatch(r'[A-Za-z0-9_-]{1,80}',artifact) else 'Configured artifact'
    mode = status.get('mode') if status.get('mode') in ('hybrid','lstm','rules-only') else 'unknown'
    return {'mode':mode,'mode_label':mode_name(mode),'artifact':artifact,
            'available':not bool(status.get('error')),
            'error': 'Rules-only operation; no active neural model.' if mode=='rules-only' else ('Model status requires local inspection.' if status.get('error') else None),
            'last_error':bool(status.get('last_inference_error'))}


def common(page, title):
    newest = query('SELECT id FROM security_events ORDER BY id DESC LIMIT 1',fetch=True)
    return dict(active_page=page,page_title=title,detection_status=public_status(),
                latest_event_id=newest[0][0] if newest else None,
                snapshot=datetime.now(timezone.utc).strftime('%d %b %Y, %H:%M UTC'))


def distributions(counts):
    total = sum(counts.values()); peak = max(counts.values(),default=1)
    return [dict(label=k,count=v,percent=round(100*v/peak,2) if peak else 0,
                 share=round(100*v/total,1) if total else 0) for k,v in sorted(counts.items(),key=lambda x:(-x[1],str(x[0])))]


def activity(events):
    counts = Counter(); unknown = 0
    for event in events:
        try:
            stamp = datetime.fromisoformat(event['timestamp'].replace('Z','+00:00'))
            stamp = stamp.replace(tzinfo=timezone.utc) if stamp.tzinfo is None else stamp.astimezone(timezone.utc)
            counts[stamp.date().isoformat()] += 1
        except (ValueError,TypeError):
            unknown += 1
    days = sorted(counts)[-14:]
    peak = max((counts[d] for d in days),default=0)
    ceiling = max(1,math.ceil(peak/4)*4)
    points=[]
    for i,d in enumerate(days):
        x = 50+i*620/max(1,len(days)-1) if len(days)>1 else 360
        y = 174-130*counts[d]/ceiling
        points.append(dict(day=d,label=d[5:],count=counts[d],x=round(x,2),y=round(y,2)))
    return dict(points=points,polyline=' '.join(f'{p["x"]},{p["y"]}' for p in points),
                ceiling=ceiling,unknown=unknown,all_days=dict(sorted(counts.items())))


def decision_chart(events):
    counts=Counter(e['decision'] for e in events)
    total=len(events); start=0; segments=[]
    for key,label,color in [('ALLOW','Allow','#55d6aa'),('BLOCK','Block','#fb7c89'),('REVIEW','Review','#f5c46a'),('UNSPECIFIED','Unspecified','#8d9daf')]:
        value=counts[key]
        if key=='UNSPECIFIED' and not value:continue
        percent=value*100/total if total else 0
        segments.append(dict(key=key,label=label,count=value,percent=round(percent,1),color=color,
                             dash=round(percent,4),offset=round(-start,4)))
        start+=percent
    return dict(total=total,segments=segments)


def overview():
    events,summary=read_window()
    return render_template('admin.html',**common('overview','Security Overview'),soc=summary,
                           events=events[:6],activity=activity(events),decisions=decision_chart(events))


def filter_values():
    values={k:request.args.get(k,'').strip() for k in ('q','decision','endpoint','source','date_from','date_to')}
    if len(values['q'])>120 or len(values['endpoint'])>255:abort(400,'Filter value is too long')
    if values['decision'] not in ('','ALLOW','BLOCK','REVIEW','UNSPECIFIED'):abort(400,'Unknown decision filter')
    if values['source'] not in ('',*SOURCE_NAMES):abort(400,'Unknown source filter')
    for key in ('date_from','date_to'):
        if values[key]:
            if not re.fullmatch(r'\d{4}-\d{2}-\d{2}',values[key]):abort(400,'Use ISO dates for date filters')
            try:date.fromisoformat(values[key])
            except ValueError:abort(400,'Use ISO dates for date filters')
    if values['date_from'] and values['date_to'] and values['date_from']>values['date_to']:
        abort(400,'The start date must not follow the end date')
    return values


@soc_pages.get('/events')
def events_page():
    filters=filter_values(); clauses=[];params=[]
    if filters['q']:
        literal=filters['q'].lower().replace('!','!!').replace('%','!%').replace('_','!_')
        fields=('CAST(id AS CHAR)','endpoint','decision','risk','category','indicators','mode','decision_source')
        clauses.append('('+' OR '.join(f"LOWER({f}) LIKE %s ESCAPE '!'" for f in fields)+')')
        params.extend(['%'+literal+'%']*len(fields))
    if filters['decision']:
        if filters['decision']=='UNSPECIFIED':clauses.append("(decision IS NULL OR decision NOT IN ('ALLOW','BLOCK','REVIEW'))")
        else:clauses.append('decision=%s');params.append(filters['decision'])
    if filters['endpoint']:clauses.append('endpoint=%s');params.append(filters['endpoint'])
    if filters['source']:clauses.append('('+SOURCE_SQL+')=%s');params.append(filters['source'])
    # Stored timestamps are UTC ISO values. Compare date prefixes consistently
    # across SQLite/MySQL; malformed/missing dates do not match bounded filters.
    if filters['date_from']:clauses.append('SUBSTR(timestamp,1,10)>=%s');params.append(filters['date_from'])
    if filters['date_to']:clauses.append('SUBSTR(timestamp,1,10)<=%s');params.append(filters['date_to'])
    where=' WHERE '+' AND '.join(clauses) if clauses else ''
    total=query('SELECT COUNT(*) FROM security_events'+where,tuple(params),True)[0][0]
    try:page=max(1,int(request.args.get('page','1')))
    except ValueError:abort(400,'Invalid page number')
    per_page=20;pages=max(1,math.ceil(total/per_page));page=min(page,pages)
    rows=query('SELECT '+','.join(COLUMNS)+' FROM security_events'+where+' ORDER BY id DESC LIMIT %s OFFSET %s',
               tuple(params)+(per_page,(page-1)*per_page),True)
    choices=[r[0] for r in query("SELECT DISTINCT endpoint FROM security_events WHERE endpoint IS NOT NULL ORDER BY endpoint",fetch=True)]
    def link(number):
        return url_for('soc_pages.events_page')+'?'+urlencode({**{k:v for k,v in filters.items() if v},'page':number})
    return render_template('soc/events.html',**common('events','Security Events'),events=[event_view(r) for r in rows],
        filters=filters,endpoints=choices,source_names=SOURCE_NAMES,total=total,page=page,pages=pages,
        first=(page-1)*per_page+1 if total else 0,last=min(page*per_page,total),
        previous=link(page-1) if page>1 else None,next_page=link(page+1) if page<pages else None)


@soc_pages.get('/events/<int:event_id>')
def event_details(event_id):
    rows=query('SELECT '+','.join(COLUMNS)+' FROM security_events WHERE id=%s',(event_id,),True)
    if not rows:abort(404)
    return render_template('soc/detail.html',**common('details','Event Details'),event=event_view(rows[0]))


@soc_pages.get('/ai')
def ai_page():
    events,summary=read_window()
    scored=[e for e in events if e['model_probability'] is not None][:15]
    return render_template('soc/ai.html',**common('ai','AI Detection'),scored=scored,soc=summary)


@soc_pages.get('/analysis')
def analysis_page():
    events,summary=read_window()
    sources=Counter(e['source_label'] for e in events)
    return render_template('soc/analysis.html',**common('analysis','Threat Analysis'),soc=summary,
        activity=activity(events),decisions=decision_chart(events),
        endpoints=distributions(summary['endpoints']),categories=distributions(summary['categories']),
        sources=distributions(sources))


@soc_pages.get('/system')
def system_page():
    return render_template('soc/system.html',**common('system','System Information'))
