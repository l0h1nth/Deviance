import {Filter, Search, SlidersHorizontal} from 'lucide-react';import {useState} from 'react';import {AlertTable} from './Overview';import type {Alert} from '../types';

export function Alerts({alerts,onSelect}:{alerts:Alert[];onSelect:(a:Alert)=>void}){
  const[q,setQ]=useState(''),[severity,setSeverity]=useState('all');
  const shown=alerts.filter(a=>(severity==='all'||a.severity===severity)&&JSON.stringify(a).toLowerCase().includes(q.toLowerCase()));
  return <><header className="page-head"><div><span className="eyebrow">DETECTION MANAGEMENT</span><h1>Detection queue</h1><p>Prioritize, investigate, and disposition model-generated behavioral findings.</p></div><div className="page-controls"><button><SlidersHorizontal/> Edit columns</button><button><Filter/> Saved views</button></div></header>
    <section className="queue-toolbar"><div className="search"><Search/><input placeholder="Search entity, host, detection, status…" value={q} onChange={e=>setQ(e.target.value)}/><kbd>/</kbd></div><div className="severity-tabs">{['all','critical','high','medium','low'].map(value=><button className={severity===value?'active':''} onClick={()=>setSeverity(value)} key={value}>{value}<span>{value==='all'?alerts.length:alerts.filter(a=>a.severity===value).length}</span></button>)}</div></section>
    <section className="panel alerts full"><div className="queue-count"><b>{shown.length}</b> detections <span>Sorted by newest first</span></div><AlertTable alerts={shown} onSelect={onSelect}/></section></>;
}
