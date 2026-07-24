import {useEffect,useMemo,useRef,useState} from 'react';
import {Pause,Play} from 'lucide-react';
import type {LiveEvent} from '../types';
import type {StreamState} from '../hooks/useLive';
import {RiskPill} from './RiskPill';

export function LiveActivity({events,connection,onSelect}:{events:LiveEvent[];connection:StreamState;onSelect:(event:LiveEvent)=>void}){
  const[pausedEvents,setPausedEvents]=useState<LiveEvent[]|null>(null),[autoScroll,setAutoScroll]=useState(true),[alertsOnly,setAlertsOnly]=useState(false),[clock,setClock]=useState(()=>Date.now());
  const wrap=useRef<HTMLDivElement>(null),paused=pausedEvents!==null,displayed=pausedEvents||events;
  const shown=alertsOnly?displayed.filter(event=>event.alert_id):displayed;
  const eps=useMemo(()=>{const cutoff=clock-5000;return events.filter(event=>new Date(event.timestamp).getTime()>=cutoff).length/5},[events,clock]);
  useEffect(()=>{const timer=setInterval(()=>setClock(Date.now()),1000);return()=>clearInterval(timer)},[]);
  useEffect(()=>{if(autoScroll&&!paused&&wrap.current)wrap.current.scrollTop=0},[events,autoScroll,paused]);
  return <section className="live-activity clean-card"><div className="live-head"><div><span className="eyebrow">SYNTHETIC REAL-TIME SECURITY EVENTS</span><h2>Live activity</h2><p>Events shown here are outputs from the persisted ML inference path.</p></div><div className="live-stats"><span className={`connection ${connection}`}><i/>{connection}</span><span><b>{eps.toFixed(1)}</b> events/sec</span></div></div>
    <div className="live-controls"><button onClick={()=>setPausedEvents(paused?null:[...events])}>{paused?<Play/>:<Pause/>}{paused?'Resume':'Pause'}</button><label><input type="checkbox" checked={autoScroll} onChange={event=>setAutoScroll(event.target.checked)}/> Auto-scroll</label><div className="segmented"><button className={!alertsOnly?'active':''} onClick={()=>setAlertsOnly(false)}>All events</button><button className={alertsOnly?'active':''} onClick={()=>setAlertsOnly(true)}>Alerts only</button></div></div>
    <div className="live-table-wrap" ref={wrap}><table className="live-table"><thead><tr><th>Timestamp</th><th>User</th><th>Device</th><th>Event</th><th>Location</th><th>Auth</th><th>Predicted class</th><th>Anomaly</th><th>Risk</th><th>Latency</th></tr></thead><tbody>{shown.map(event=><tr key={event.event_id} onClick={()=>onSelect(event)}><td><time>{new Date(event.timestamp).toLocaleTimeString()}</time></td><td><b>{event.user_id}</b></td><td>{event.device_id}</td><td>{event.event_type?.replaceAll('_',' ')}</td><td>{event.location?.city}, {event.location?.country}</td><td><span className={`auth-result ${event.authentication_result}`}>{event.authentication_result}</span></td><td><b>{event.display_attack||event.predicted_attack?.replaceAll('_',' ')}</b></td><td>{event.anomaly_score?.toFixed(3)}</td><td><RiskPill score={event.risk_score} severity={event.severity}/></td><td>{event.latency_ms?.toFixed(1)} ms</td></tr>)}</tbody></table>{!shown.length&&<div className="stream-empty"><i/><h3>Waiting for synthetic security events</h3><p>Start a simulation to watch validated model outputs arrive without refreshing.</p></div>}</div>
  </section>;
}
