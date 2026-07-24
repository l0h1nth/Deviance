import {useEffect,useState} from 'react';
import {Pause,Play,Square,X} from 'lucide-react';
import {api} from '../services/api';
import type {SimulationStatus} from '../types';

const scenarios=['mixed','brute_force','credential_misuse','credential_stuffing','lateral_movement','impossible_travel','device_spoofing','low_slow_exfiltration','cold_start','concept_drift','insider_drift'];

export function SimulationModal({onClose}:{onClose:()=>void}){
  const[scenario,setScenario]=useState('mixed'),[intervalMs,setIntervalMs]=useState(1000),[count,setCount]=useState(30);
  const[state,setState]=useState<SimulationStatus|null>(null),[error,setError]=useState('');
  const running=state?.status==='running'||state?.status==='stopping';
  useEffect(()=>{api.simulationStatus().then(setState).catch(()=>{})},[]);
  useEffect(()=>{if(!running)return;const timer=setInterval(()=>api.simulationStatus().then(setState).catch(()=>{}),500);return()=>clearInterval(timer)},[running]);
  const start=async()=>{setError('');try{setState(await api.startSimulation(scenario,intervalMs,count))}catch(reason){setError(reason instanceof Error?reason.message:'Unable to start simulation')}};
  const stop=async()=>{setError('');try{setState(await api.stopSimulation())}catch(reason){setError(reason instanceof Error?reason.message:'Unable to stop simulation')}};
  return <div className="modal-backdrop" role="presentation" onMouseDown={event=>event.target===event.currentTarget&&onClose()}><section className="simulation-modal" role="dialog" aria-modal="true" aria-labelledby="simulation-title">
    <header><div><span className="eyebrow">SYNTHETIC REAL-TIME SECURITY EVENTS</span><h2 id="simulation-title">Run security simulation</h2><p>Every event follows the production path: validation, 24-feature engineering, Isolation Forest and GRU anomaly scoring, calibrated classification, incident grouping, explanation, and live broadcast.</p></div><button className="icon-button" onClick={onClose} aria-label="Close simulation"><X/></button></header>
    <div className="simulation-form"><label>Scenario<select value={scenario} disabled={running} onChange={event=>{const value=event.target.value;setScenario(value);if(['concept_drift','insider_drift'].includes(value)&&count<40)setCount(45)}}>{scenarios.map(value=><option key={value} value={value}>{value.replaceAll('_',' ')}</option>)}</select></label>
      <label>Interval<select value={intervalMs} disabled={running} onChange={event=>setIntervalMs(Number(event.target.value))}><option value={500}>500 ms</option><option value={1000}>1 second</option><option value={2000}>2 seconds</option></select></label>
      <label>Event count<input type="number" min={['concept_drift','insider_drift'].includes(scenario)?40:1} max={500} disabled={running} value={count} onChange={event=>setCount(Math.max(['concept_drift','insider_drift'].includes(scenario)?40:1,Math.min(500,Number(event.target.value))))}/></label></div>
    <div className="simulation-progress"><div><span>Status</span><strong className={`simulation-state ${state?.status||'idle'}`}>{state?.status?.replaceAll('_',' ')||'idle'}</strong></div><div><span>Processed</span><strong>{state?.processed_events||0} / {state?.event_count||count}</strong></div><div><span>Alerts created</span><strong>{state?.alert_count||0}</strong></div></div>
    <div className="progress-track"><i style={{width:`${state?.event_count?Math.min(100,state.processed_events/state.event_count*100):0}%`}}/></div>
    {state?.last_error&&<div className="login-error">{state.last_error}</div>}{error&&<div className="login-error">{error}</div>}
    <footer><small><Pause/> Closing this modal does not stop a running simulation.</small>{running?<button className="danger-control" onClick={stop}><Square/> Stop simulation</button>:<button className="primary-control" onClick={start}><Play/> Start simulation</button>}</footer>
  </section></div>;
}
