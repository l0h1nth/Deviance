import {
  Activity, Bell, BrainCircuit, Command, GitCompareArrows, LayoutGrid,
  Moon, Search, ShieldCheck, Sun, Users,
} from 'lucide-react';
import {useCallback, useEffect, useState} from 'react';
import {api} from './services/api';
import type {Alert, AlertDetail, Metrics} from './types';
import {Overview} from './pages/Overview';
import {Alerts} from './pages/Alerts';
import {Investigation} from './pages/Investigation';
import {ModelPage} from './pages/Model';
import {DriftPage} from './pages/Drift';
import {UsersPage} from './pages/Users';
import {useLive} from './hooks/useLive';

type Page='overview'|'alerts'|'model'|'drift'|'users'|'investigation';
type Theme='dark'|'light';
const pageLabels:Record<Page,string>={overview:'Operations',alerts:'Detection queue',model:'Model health',drift:'Behavior drift',users:'Identities',investigation:'Incident workspace'};

const navigation = [
  {section:'OPERATIONS', items:[['overview', LayoutGrid, 'Operations'], ['alerts', ShieldCheck, 'Detection queue']]},
  {section:'INTELLIGENCE', items:[['users', Users, 'Identities'], ['model', BrainCircuit, 'Model health'], ['drift', GitCompareArrows, 'Behavior drift']]},
] as const;

export default function App(){
  const [page,setPage]=useState<Page>('overview');
  const [metrics,setMetrics]=useState<Metrics|null>(null);
  const [alerts,setAlerts]=useState<Alert[]>([]);
  const [detail,setDetail]=useState<AlertDetail|null>(null);
  const [model,setModel]=useState<any>(null);
  const [drift,setDrift]=useState<any[]>([]);
  const [theme,setTheme]=useState<Theme>(()=>(localStorage.getItem('deviance-theme') as Theme)||'dark');

  const load=useCallback(()=>{
    api.metrics().then(setMetrics).catch(()=>{});
    api.alerts().then(setAlerts).catch(()=>{});
    api.drift().then(setDrift).catch(()=>{});
  },[]);
  useEffect(()=>{load();api.model().then(setModel).catch(()=>{})},[load]);
  useEffect(()=>{document.documentElement.dataset.theme=theme;localStorage.setItem('deviance-theme',theme)},[theme]);
  useLive(load);

  const select=(alert:Alert)=>{setPage('investigation');api.alert(alert.id).then(setDetail)};
  const update=(status:string)=>detail&&api.updateAlert(detail.id,status).then(()=>api.alert(detail.id).then(setDetail).then(load));
  const currentLabel=pageLabels[page];

  return <div className="soc-shell">
    <aside className="nav-rail">
      <button className="product-mark" onClick={()=>setPage('overview')} aria-label="Deviance home"><span>D</span></button>
      <div className="rail-tools"><button className="active"><Activity/></button><button><Bell/><i>{alerts.length}</i></button></div>
      <div className="rail-foot"><span className="analyst-avatar">A1</span></div>
    </aside>

    <aside className="side-panel">
      <div className="product-name"><strong>DEVIANCE</strong><small>BEHAVIORAL SOC</small></div>
      <div className="environment"><i/><span>Production workspace</span></div>
      <nav>{navigation.map(group=><section key={group.section}><label>{group.section}</label>{group.items.map(([id,Icon,text])=><button key={id} className={page===id?'active':''} onClick={()=>setPage(id as Page)}><Icon/><span>{text}</span>{id==='alerts'&&alerts.length>0?<em>{alerts.length}</em>:null}</button>)}</section>)}</nav>
      <div className="model-state"><div><span>Detection engine</span><b><i/> Operational</b></div><small>{model?.model_version||'No active artifact'}</small></div>
    </aside>

    <section className="workbench">
      <header className="global-bar">
        <div className="breadcrumb"><Command/><span>DEVIANCE</span><b>/</b><strong>{currentLabel}</strong></div>
        <div className="global-search"><Search/><span>Search alerts, identities, hosts</span><kbd>⌘ K</kbd></div>
        <div className="bar-actions"><span className="utc-clock">UTC · LIVE</span><button className="theme-toggle" onClick={()=>setTheme(theme==='dark'?'light':'dark')} aria-label="Toggle color mode">{theme==='dark'?<Sun/>:<Moon/>}<span>{theme==='dark'?'Light':'Black'}</span></button></div>
      </header>
      <main>
        {page==='overview'&&<Overview metrics={metrics} alerts={alerts} onSelect={select}/>}
        {page==='alerts'&&<Alerts alerts={alerts} onSelect={select}/>}
        {page==='investigation'&&<Investigation detail={detail} onBack={()=>setPage('alerts')} onUpdate={update}/>}
        {page==='model'&&<ModelPage model={model}/>}
        {page==='drift'&&<DriftPage drift={drift}/>}
        {page==='users'&&<UsersPage initialUser={alerts[0]?.user_id}/>}
      </main>
    </section>
  </div>;
}
