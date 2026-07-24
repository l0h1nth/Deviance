import {Activity, AlertOctagon, Clock3, Radio, ShieldAlert, TimerReset} from 'lucide-react';
import {Area,AreaChart,CartesianGrid,ResponsiveContainer,Tooltip,XAxis,YAxis} from 'recharts';
import {StatCard} from '../components/StatCard';import {RiskPill} from '../components/RiskPill';import type {Alert,Metrics} from '../types';

export function Overview({metrics,alerts,onSelect}:{metrics:Metrics|null;alerts:Alert[];onSelect:(a:Alert)=>void}){
  if(!metrics)return <div className="loading">Connecting to detection telemetry…</div>;
  const critical=alerts.filter(a=>a.severity==='critical').length;
  return <>
    <header className="page-head"><div><span className="eyebrow">SECURITY OPERATIONS</span><h1>Detection command center</h1><p>Behavioral detections, incident pressure, and model telemetry across the organization.</p></div><div className="page-controls"><button>Last 24 hours</button><button className="live"><i/> Live</button></div></header>
    <section className="threat-banner"><div><Radio/><span>DETECTION POSTURE</span><strong>{critical?'Elevated':'Nominal'}</strong></div><p>{critical?`${critical} critical detections require immediate triage.`:'No critical behavioral detections in the active queue.'}</p><span className="engine-latency">PIPELINE {metrics.average_detection_latency_ms} MS</span></section>
    <section className="stats">
      <StatCard label="Telemetry processed" value={metrics.total_events.toLocaleString()} detail="events in current store" icon={<Activity/>}/>
      <StatCard label="Detection queue" value={metrics.total_alerts} detail={`${metrics.open_investigations} open / investigating`} icon={<ShieldAlert/>} tone="warning"/>
      <StatCard label="Critical priority" value={metrics.critical_alerts} detail="highest response SLA" icon={<AlertOctagon/>} tone="danger"/>
      <StatCard label="Mean detection time" value={`${metrics.average_detection_latency_ms} ms`} detail="ingest to verdict" icon={<Clock3/>} tone="good"/>
    </section>
    <section className="operations-grid">
      <article className="panel trend-panel"><div className="panel-title"><div><span>RISK TELEMETRY</span><h2>Model risk over event sequence</h2></div><div className="legend"><i/> Risk score</div></div><ResponsiveContainer width="100%" height={245}><AreaChart data={metrics.risk_trend}><defs><linearGradient id="riskFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="var(--risk)" stopOpacity={.28}/><stop offset="100%" stopColor="var(--risk)" stopOpacity={0}/></linearGradient></defs><CartesianGrid stroke="var(--grid)" vertical={false}/><XAxis dataKey="id" tick={{fill:'var(--muted)',fontSize:9}} axisLine={false} tickLine={false}/><YAxis domain={[0,100]} tick={{fill:'var(--muted)',fontSize:9}} axisLine={false} tickLine={false}/><Tooltip contentStyle={{background:'var(--surface-raised)',border:'1px solid var(--line)',borderRadius:0,color:'var(--text)'}}/><Area type="stepAfter" dataKey="risk" stroke="var(--risk)" fill="url(#riskFill)" strokeWidth={2}/></AreaChart></ResponsiveContainer></article>
      <article className="panel distribution-panel"><div className="panel-title"><div><span>DETECTION DISTRIBUTION</span><h2>Model verdicts</h2></div><TimerReset/></div><div className="bars">{Object.entries(metrics.attacks_by_type).sort((a,b)=>b[1]-a[1]).map(([name,count])=><div key={name}><label><span>{name.replaceAll('_',' ')}</span><b>{count}</b></label><div><i style={{width:`${Math.max(2,Math.min(100,count/Math.max(...Object.values(metrics.attacks_by_type),1)*100))}%`}}/></div></div>)}</div></article>
    </section>
    <section className="panel alerts queue-panel"><div className="panel-title"><div><span>ACTIVE TRIAGE</span><h2>Detection queue</h2></div><div className="queue-meta"><i/>{alerts.filter(a=>a.status==='open').length} unassigned</div></div><AlertTable alerts={alerts.slice(0,9)} onSelect={onSelect}/></section>
  </>;
}

export function AlertTable({alerts,onSelect}:{alerts:Alert[];onSelect:(a:Alert)=>void}){return <div className="table-wrap"><table><thead><tr><th>Created</th><th>Entity</th><th>Detection</th><th>Risk / Severity</th><th>Confidence</th><th>Workflow</th><th></th></tr></thead><tbody>{alerts.map(a=><tr key={a.id} onClick={()=>onSelect(a)}><td><time>{new Date(a.timestamp).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'})}</time><small>{new Date(a.timestamp).toLocaleDateString()}</small></td><td><b>{a.user_id}</b><small>{a.device_id}</small></td><td><span className="detection-name">{a.predicted_attack.replaceAll('_',' ')}</span></td><td><RiskPill score={a.risk_score} severity={a.severity}/></td><td><span className="confidence"><i style={{width:`${Math.round(a.confidence*100)}%`}}/></span><small>{Math.round(a.confidence*100)}%</small></td><td><span className={`status ${a.status}`}>{a.status.replaceAll('_',' ')}</span></td><td className="row-arrow">→</td></tr>)}</tbody></table>{!alerts.length&&<div className="empty">No detections in queue. Start the stream simulator to send telemetry.</div>}</div>}

