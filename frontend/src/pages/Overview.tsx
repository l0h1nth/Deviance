import {Check,ChevronDown,Play} from 'lucide-react';
import {Area,AreaChart,CartesianGrid,ResponsiveContainer,Tooltip,XAxis,YAxis} from 'recharts';
import {RiskPill} from '../components/RiskPill';import type {Alert,Metrics} from '../types';

const palette=['#d8387e','#f6bd19','#42bfd3','#7656c9','#58b982','#ef7c45'];

export function Overview({metrics,alerts,model,onSelect}:{metrics:Metrics|null;alerts:Alert[];model:any;onSelect:(a:Alert)=>void}){
  if(!metrics)return <div className="loading">Loading behavioral telemetry…</div>;
  const open=alerts.filter(a=>a.status==='open').length, investigating=alerts.filter(a=>a.status==='investigating').length, critical=alerts.filter(a=>a.severity==='critical').length;
  const fp=Math.round(metrics.false_positive_rate*100),maxAttack=Math.max(...Object.values(metrics.attacks_by_type),1);
  const riskMix=`conic-gradient(#d8387e 0 ${Math.max(critical/Math.max(metrics.total_alerts,1)*100,8)}%, #f6bd19 0 42%, #42bfd3 0 70%, #7656c9 0 100%)`;
  return <>
    <div className="overview-tabs"><button className="active">General</button><button>Live activity</button><button>Model insights</button><button className="run-demo"><Play/> Run simulation</button></div>

    <section className="summary-card">
      <div className="section-heading"><h2>General information</h2><span>Updated just now</span></div>
      <div className="summary-fields">
        <Info label="Detection model" value="Isolation Forest + RF"/>
        <Info label="Monitoring window" value="Real-time / rolling 5 min"/>
        <Info label="Feature schema" value={model?.feature_schema_version||'1.0.0'}/>
        <Info label="Alert threshold" value={model?.alert_threshold?`${model.alert_threshold.toFixed(1)} risk`:'50 risk'}/>
        <Info label="Mean latency" value={`${metrics.average_detection_latency_ms} ms`} accent/>
        <Info label="Model version" value={model?.model_version||'Not trained'}/>
      </div>
    </section>

    <section className="overview-cards">
      <article className="clean-card status-card"><div className="section-heading"><h2>Detections by status</h2><button>Last 24 hours <ChevronDown/></button></div><div className="status-content"><div className="donut" style={{background:riskMix}}><div><span>Total</span><strong>{metrics.total_alerts}</strong></div></div><div className="status-metrics"><CircleMetric value={open} label="Pending" color="#d8387e" total={metrics.total_alerts}/><CircleMetric value={investigating} label="In progress" color="#f6bd19" total={metrics.total_alerts}/><CircleMetric value={Math.max(0,metrics.total_alerts-open-investigating)} label="Reviewed" color="#42bfd3" total={metrics.total_alerts}/><CircleMetric value={critical} label="Critical" color="#7656c9" total={metrics.total_alerts}/></div></div></article>

      <article className="clean-card owner-card"><div className="section-heading"><h2>Detections by attack class</h2><span>Model verdicts</span></div><div className="attack-bars">{Object.entries(metrics.attacks_by_type).sort((a,b)=>b[1]-a[1]).slice(0,5).map(([name,count],index)=><div key={name}><span className="class-avatar" style={{background:palette[index]}}>{name.slice(0,2).toUpperCase()}</span><div><label>{name.replaceAll('_',' ')}</label><span><i style={{width:`${Math.max(6,count/maxAttack*100)}%`,background:palette[index]}}/></span></div><strong>{count}</strong></div>)}</div></article>
    </section>

    <section className="clean-card timeline-card"><div className="section-heading"><h2>Risk timeline</h2><div className="timeline-legend"><span><i className="normal"/>Normal range</span><span><i className="elevated"/>Elevated risk</span></div></div><ResponsiveContainer width="100%" height={190}><AreaChart data={metrics.risk_trend}><defs><linearGradient id="cleanRisk" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#7656c9" stopOpacity={.2}/><stop offset="100%" stopColor="#7656c9" stopOpacity={0}/></linearGradient></defs><CartesianGrid stroke="var(--grid)" strokeDasharray="4 4" vertical={false}/><XAxis dataKey="id" tick={{fill:'var(--muted)',fontSize:9}} axisLine={false} tickLine={false}/><YAxis domain={[0,100]} tick={{fill:'var(--muted)',fontSize:9}} axisLine={false} tickLine={false}/><Tooltip contentStyle={{background:'var(--surface)',border:'1px solid var(--line)',borderRadius:10,color:'var(--text)'}}/><Area type="monotone" dataKey="risk" stroke="#7656c9" fill="url(#cleanRisk)" strokeWidth={2}/></AreaChart></ResponsiveContainer></section>

    <section className="clean-card recent-card"><div className="section-heading"><h2>Recent detections</h2><button>View all <span>→</span></button></div><AlertTable alerts={alerts.slice(0,6)} onSelect={onSelect}/></section>
  </>;
}

function Info({label,value,accent=false}:{label:string;value:string;accent?:boolean}){return <div className="info-field"><span>{label}</span><strong>{value}</strong>{accent&&<div className="latency-track"><i/></div>}</div>}
function CircleMetric({value,label,color,total}:{value:number;label:string;color:string;total:number}){const percent=Math.max(8,value/Math.max(total,1)*100);return <div className="circle-metric"><div style={{background:`conic-gradient(${color} ${percent}%, var(--soft-fill) 0)`}}><span>{value}</span></div><label>{label}</label></div>}

export function AlertTable({alerts,onSelect}:{alerts:Alert[];onSelect:(a:Alert)=>void}){return <div className="table-wrap"><table><thead><tr><th>Time</th><th>Identity</th><th>Detection</th><th>Risk</th><th>Confidence</th><th>Status</th></tr></thead><tbody>{alerts.map(a=><tr key={a.id} onClick={()=>onSelect(a)}><td><time>{new Date(a.timestamp).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'})}</time></td><td><b>{a.user_id}</b><small>{a.device_id}</small></td><td className="detection-name">{a.predicted_attack.replaceAll('_',' ')}</td><td><RiskPill score={a.risk_score} severity={a.severity}/></td><td>{Math.round(a.confidence*100)}%</td><td><span className={`status ${a.status}`}>{a.status==='closed'?<Check/>:null}{a.status.replaceAll('_',' ')}</span></td></tr>)}</tbody></table>{!alerts.length&&<div className="empty">No detections yet. Start the simulator to populate this dashboard.</div>}</div>}
