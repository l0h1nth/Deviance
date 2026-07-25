import {ArrowRight,CheckCircle2,CircleGauge,GitCompareArrows,LockKeyhole,RefreshCcw,ShieldAlert,UsersRound,XCircle} from 'lucide-react';
import {useState} from 'react';
import type {DriftResponse,DriftReviewAction} from '../types';

const percent=(value:number)=>`${(Number(value||0)*100).toFixed(1)}%`;
const progress=(count:number,target:number)=>`${Math.min(100,count/Math.max(target,1)*100)}%`;
const finalStatuses=new Set(['approved_adaptation','rejected_change','dismissed']);

export function DriftPage({drift,onReview}:{drift:DriftResponse;onReview:(id:number,action:DriftReviewAction,comment:string)=>Promise<void>}){
  const events=drift.events||[],windows=drift.windows||[],summary=drift.summary;
  const[working,setWorking]=useState<string>(),[notes,setNotes]=useState<Record<number,string>>({}),[error,setError]=useState('');
  const act=async(id:number,action:DriftReviewAction)=>{
    if(action==='approve_adaptation'&&!window.confirm('Promote this reviewed behavior to the new trusted baseline?'))return;
    if(action==='reject_change'&&!window.confirm('Reject this change and retain the previous trusted baseline?'))return;
    setWorking(`${id}:${action}`);setError('');
    try{await onReview(id,action,notes[id]||'');setNotes(current=>({...current,[id]:''}))}catch(reason){setError(reason instanceof Error?reason.message:'Unable to update drift review')}finally{setWorking(undefined)}
  };
  return <>
    <header className="page-head drift-page-head"><div><span className="eyebrow">BEHAVIOR GOVERNANCE</span><h1>Concept drift</h1><p>Detect legitimate behavior change without letting attacks poison the learned baseline.</p></div><span className={`drift-state ${summary?.state||'stable'}`}><i/>{(summary?.state||'stable').replaceAll('_',' ')}</span></header>

    <section className="drift-command panel">
      <div className="drift-command-copy"><span className="eyebrow">TRUSTED ADAPTATION</span><h2>Behavior can evolve. The baseline cannot move silently.</h2><p>Only low-risk trusted telemetry enters these windows. A meaningful distribution shift freezes the affected signal until an analyst decides what happens next.</p></div>
      <div className="drift-command-facts"><div><LockKeyhole/><span><b>Poisoning guard</b><small>Suspicious events excluded</small></span></div><div><RefreshCcw/><span><b>Manual promotion</b><small>No automatic retraining</small></span></div></div>
    </section>

    <section className="drift-kpis">
      <article><span>Pending review</span><strong className={summary?.pending_reviews?'attention':''}>{summary?.pending_reviews??0}</strong><small>Frozen findings requiring a decision</small></article>
      <article><span>Monitored identities</span><strong>{summary?.monitored_entities??0}</strong><small>Entities with durable drift state</small></article>
      <article><span>Trusted observations</span><strong>{summary?.trusted_events??0}</strong><small>Low-risk events admitted to windows</small></article>
      <article><span>Signal coverage</span><strong>{summary?.signals_monitored??8}</strong><small>Identity, device, access and model signals</small></article>
    </section>

    <section className="drift-pipeline panel" aria-label="Concept drift lifecycle">
      <div><span className="pipeline-icon"><LockKeyhole/></span><b>Trust gate</b><small>Low-risk normal only</small></div><ArrowRight/>
      <div><span className="pipeline-index">01</span><b>Reference</b><small>{summary?.reference_size??20} trusted events</small></div><ArrowRight/>
      <div><span className="pipeline-index">02</span><b>Current</b><small>{summary?.current_size??20} trusted events</small></div><ArrowRight/>
      <div><span className="pipeline-icon"><GitCompareArrows/></span><b>Shift test</b><small>Effect size + KS distance</small></div><ArrowRight/>
      <div><span className="pipeline-icon guarded"><ShieldAlert/></span><b>Review gate</b><small>Approve or preserve</small></div>
    </section>

    <div className="drift-section-title"><div><span className="eyebrow">LIVE WINDOWS</span><h2>Baseline coverage</h2></div><small>{windows.length} active {windows.length===1?'identity':'identities'}</small></div>
    <section className="drift-window-grid">
      {windows.map(item=><article className="panel drift-window" key={item.entity}><header><div><span className={`window-status ${item.status}`}>{item.status.replaceAll('_',' ')}</span><h3>{item.entity}</h3></div><span className="baseline-version">v{item.baseline_version}</span></header><div className="window-bars"><label><span>Reference window</span><b>{item.reference_window.count}/{item.reference_window.target}</b></label><div><i className="reference" style={{width:progress(item.reference_window.count,item.reference_window.target)}}/></div><label><span>Current window</span><b>{item.current_window.count}/{item.current_window.target}</b></label><div><i className="current" style={{width:progress(item.current_window.count,item.current_window.target)}}/></div></div><footer><span><LockKeyhole/>Trusted only</span>{item.flagged_features.length>0?<b>{item.flagged_features.length} signal{item.flagged_features.length===1?'':'s'} frozen</b>:<small>{item.last_observed_at?`Updated ${new Date(item.last_observed_at).toLocaleTimeString()}`:'Waiting for telemetry'}</small>}</footer></article>)}
      {!windows.length&&<div className="panel drift-empty-window"><CircleGauge/><div><h3>No active drift windows</h3><p>Run the concept drift simulation with 40 events. The first 20 create the trusted reference; the next 20 challenge it.</p></div></div>}
    </section>

    <div className="drift-section-title review-title"><div><span className="eyebrow">ANALYST REVIEW</span><h2>Distribution changes</h2></div><small>{events.length} recorded finding{events.length===1?'':'s'}</small></div>
    {error&&<div className="drift-error">{error}</div>}
    <section className="drift-findings">
      {events.map(item=>{const final=finalStatuses.has(item.review_status);return <article className={`panel drift-finding ${item.severity}`} key={item.id}>
        <header><div className="finding-identity"><span className={`severity-dot ${item.severity}`}/><div><span>{item.domain} signal · {new Date(item.detected_at).toLocaleString()}</span><h3>{item.feature.replaceAll('_',' ')}</h3><small>{item.subject_id}</small></div></div><div className="finding-verdict"><span className={`review-status ${item.review_status}`}>{item.review_status.replaceAll('_',' ')}</span><strong>{percent(item.drift_confidence)}<small>confidence</small></strong></div></header>
        <div className="drift-comparison"><div><span>Trusted reference</span><strong>{Number(item.previous_distribution.mean||0).toFixed(2)}</strong><small>σ {Number(item.previous_distribution.std||0).toFixed(2)} · n {item.previous_distribution.count||0}</small></div><span className="comparison-arrow"><ArrowRight/></span><div><span>Challenged window</span><strong>{Number(item.current_distribution.mean||0).toFixed(2)}</strong><small>σ {Number(item.current_distribution.std||0).toFixed(2)} · n {item.current_distribution.count||0}</small></div><dl><div><dt>Effect</dt><dd>{item.magnitude.toFixed(1)}σ</dd></div><div><dt>KS distance</dt><dd>{item.ks_distance.toFixed(2)}</dd></div><div><dt>Baseline</dt><dd>v{item.baseline_version}</dd></div></dl></div>
        <div className="drift-recommendation"><ShieldAlert/><div><b>Analyst guidance</b><p>{item.recommendation}. Review the underlying access evidence before changing the baseline.</p></div></div>
        {!final?<footer className="drift-actions"><input aria-label={`Review note for ${item.feature}`} value={notes[item.id]||''} onChange={event=>setNotes(current=>({...current,[item.id]:event.target.value}))} placeholder="Add review evidence or ticket reference"/><div><button disabled={!!working} onClick={()=>act(item.id,'investigate')}><CircleGauge/>Investigate</button><button className="reject" disabled={!!working} onClick={()=>act(item.id,'reject_change')}><XCircle/>Reject change</button><button className="approve" disabled={!!working} onClick={()=>act(item.id,'approve_adaptation')}><CheckCircle2/>Approve baseline</button></div></footer>:<footer className="drift-resolution"><CheckCircle2/><span><b>{item.review_status.replaceAll('_',' ')}</b><small>{item.review_history.at(-1)?.comment||'Disposition recorded by the analyst'}</small></span></footer>}
      </article>})}
      {!events.length&&<div className="panel drift-empty"><GitCompareArrows/><h3>No behavior shifts detected</h3><p>The monitor is ready. Simulate <b>concept drift</b> with exactly 40 events to exercise the complete review lifecycle.</p></div>}
    </section>
  </>;
}
