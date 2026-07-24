import {
  Bell, BrainCircuit, ChevronDown, CircleHelp, GitCompareArrows,
  LayoutDashboard, LogOut, Moon, ShieldCheck, Sun, Users,
} from 'lucide-react';
import {useCallback, useEffect, useState} from 'react';
import {api,authToken,type AuthUser} from './services/api';
import type {Alert, AlertDetail, Metrics} from './types';
import {Overview} from './pages/Overview';
import {Alerts} from './pages/Alerts';
import {Investigation} from './pages/Investigation';
import {ModelPage} from './pages/Model';
import {DriftPage} from './pages/Drift';
import {UsersPage} from './pages/Users';
import {Login} from './pages/Login';
import {useLive} from './hooks/useLive';

type Page='overview'|'alerts'|'model'|'drift'|'users'|'investigation';
type Theme='dark'|'light';
const pageLabels:Record<Page,string>={overview:'Behavior overview',alerts:'Detection queue',model:'Model performance',drift:'Concept drift',users:'User behavior',investigation:'Alert investigation'};
const navigation = [
  ['overview',LayoutDashboard,'Dashboard'],['alerts',ShieldCheck,'Detections'],
  ['users',Users,'Identities'],['model',BrainCircuit,'Model health'],['drift',GitCompareArrows,'Drift monitor'],
] as const;

export default function App(){
  const[page,setPage]=useState<Page>('overview'),[metrics,setMetrics]=useState<Metrics|null>(null),[alerts,setAlerts]=useState<Alert[]>([]),[detail,setDetail]=useState<AlertDetail|null>(null),[model,setModel]=useState<any>(null),[drift,setDrift]=useState<any[]>([]);
  const[theme,setTheme]=useState<Theme>(()=>(localStorage.getItem('deviance-clean-theme') as Theme)||'light');
  const[user,setUser]=useState<AuthUser|null>(null),[authReady,setAuthReady]=useState(false);
  const load=useCallback(()=>{api.metrics().then(setMetrics).catch(()=>{});api.alerts().then(setAlerts).catch(()=>{});api.drift().then(setDrift).catch(()=>{})},[]);
  useEffect(()=>{if(!authToken()){setAuthReady(true);return}api.me().then(setUser).catch(()=>api.logout()).finally(()=>setAuthReady(true))},[]);
  useEffect(()=>{if(user){load();api.model().then(setModel).catch(()=>{})}},[load,user]);
  useEffect(()=>{document.documentElement.dataset.theme=theme;localStorage.setItem('deviance-clean-theme',theme)},[theme]);
  useLive(load,!!user);
  const select=(alert:Alert)=>{setPage('investigation');api.alert(alert.id).then(setDetail)};
  const update=(status:string)=>detail&&api.updateAlert(detail.id,status).then(()=>api.alert(detail.id).then(setDetail).then(load));

  if(!authReady)return <div className="auth-loading"><span className="brand-symbol"><i/><i/><i/></span><b>DEVIANCE</b></div>;
  if(!user)return <Login onAuthenticated={setUser}/>;
  const logout=()=>{api.logout();setUser(null);setMetrics(null);setAlerts([])};

  return <div className="app-frame">
    <aside className="sidebar">
      <button className="brand" onClick={()=>setPage('overview')}><span className="brand-symbol"><i/><i/><i/></span><strong>deviance</strong></button>
      <nav>{navigation.map(([id,Icon,label])=><button key={id} className={page===id?'active':''} onClick={()=>setPage(id as Page)}><Icon/><span>{label}</span>{id==='alerts'&&alerts.length>0?<em>{alerts.length}</em>:null}</button>)}</nav>
      <div className="sidebar-status"><span><i/> Model online</span><small>{model?.model_version||'Awaiting model'}</small></div>
      <button className="collapse-control">‹</button>
    </aside>

    <section className="workspace">
      <header className="workspace-header">
        <div><h1>{pageLabels[page]}</h1><span className="active-pill"><i/> Active</span><ChevronDown/></div>
        <div className="header-actions"><button className="icon-button"><CircleHelp/></button><button className="icon-button notification"><Bell/><i/></button><button className="theme-button" onClick={()=>setTheme(theme==='light'?'dark':'light')}>{theme==='light'?<Moon/>:<Sun/>}<span>{theme==='light'?'Black':'Light'}</span></button><div className="profile"><span>AD</span><div><b>{user.username}</b><small>Administrator</small></div></div><button className="icon-button logout-button" onClick={logout} title="Sign out"><LogOut/></button></div>
      </header>
      <main>
        {page==='overview'&&<Overview metrics={metrics} alerts={alerts} model={model} onSelect={select}/>}
        {page==='alerts'&&<Alerts alerts={alerts} onSelect={select}/>}
        {page==='investigation'&&<Investigation detail={detail} onBack={()=>setPage('alerts')} onUpdate={update}/>}
        {page==='model'&&<ModelPage model={model}/>}
        {page==='drift'&&<DriftPage drift={drift}/>}
        {page==='users'&&<UsersPage initialUser={alerts[0]?.user_id}/>}
      </main>
    </section>
  </div>;
}
