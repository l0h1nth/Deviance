import {Bell,BrainCircuit,ChevronDown,ChevronsLeft,ChevronsRight,CircleHelp,GitCompareArrows,LayoutDashboard,LogOut,Moon,ShieldCheck,Sun,TrendingUp,Users} from 'lucide-react';
import {useCallback,useEffect,useMemo,useRef,useState} from 'react';
import {api,type AuthUser} from './services/api';
import type {Alert,AlertDetail,AppNotification,BehaviorRankings,DriftResponse,DriftReviewAction,LiveEvent,Metrics,Page} from './types';
import {Overview} from './pages/Overview';import {Alerts} from './pages/Alerts';import {Investigation} from './pages/Investigation';import {ModelPage} from './pages/Model';import {DriftPage} from './pages/Drift';import {BehaviorPage} from './pages/Behavior';import {UsersPage} from './pages/Users';import {Login} from './pages/Login';
import {useLive,type StreamMessage,type StreamState} from './hooks/useLive';
import {HelpDrawer} from './components/HelpDrawer';import {NotificationsPopover} from './components/NotificationsPopover';import {ModelStatusPopover} from './components/ModelStatusPopover';

type Theme='dark'|'light';
const pageLabels:Record<Page,string>={overview:'Behavior overview',alerts:'Detection queue',model:'Model performance',drift:'Concept drift',behavior:'Identity risk',users:'User behavior',investigation:'Alert investigation'};
const navigation=[['overview',LayoutDashboard,'Dashboard'],['alerts',ShieldCheck,'Detections'],['users',Users,'Identities'],['behavior',TrendingUp,'Identity risk'],['model',BrainCircuit,'Model health'],['drift',GitCompareArrows,'Drift monitor']] as const;
const READ_KEY='deviance-read-notifications',COLLAPSE_KEY='deviance-sidebar-collapsed';

export default function App(){
  const[page,setPage]=useState<Page>('overview'),[metrics,setMetrics]=useState<Metrics|null>(null),[alerts,setAlerts]=useState<Alert[]>([]),[detail,setDetail]=useState<AlertDetail|null>(null),[model,setModel]=useState<any>(null),[drift,setDrift]=useState<DriftResponse>({events:[],windows:[]});
  const[behavior,setBehavior]=useState<BehaviorRankings>({model_ready:false,threshold:0,window_days:30,rankings:[]});
  const[liveEvents,setLiveEvents]=useState<LiveEvent[]>([]),[connection,setConnection]=useState<StreamState>('connecting'),[modelStatus,setModelStatus]=useState<any>(null),[notifications,setNotifications]=useState<AppNotification[]>([]);
  const[theme,setTheme]=useState<Theme>(()=>(localStorage.getItem('deviance-clean-theme') as Theme)||'light'),[user,setUser]=useState<AuthUser|null>(null),[authReady,setAuthReady]=useState(false);
  const[collapsed,setCollapsed]=useState(()=>localStorage.getItem(COLLAPSE_KEY)==='true'),[helpOpen,setHelpOpen]=useState(false),[notificationsOpen,setNotificationsOpen]=useState(false),[modelOpen,setModelOpen]=useState(false),[selectedUser,setSelectedUser]=useState<string>();
  const[readIds,setReadIds]=useState<Set<string>>(()=>{try{return new Set(JSON.parse(localStorage.getItem(READ_KEY)||'[]'))}catch{return new Set()}});
  const refreshInFlight=useRef(false),refreshQueued=useRef(false);
  const refreshRuntime=useCallback(async()=>{
    if(refreshInFlight.current){refreshQueued.current=true;return}
    refreshInFlight.current=true;
    try{
      do{
        refreshQueued.current=false;
        await Promise.allSettled([
          api.metrics().then(setMetrics),api.alerts().then(setAlerts),
          api.drift().then(setDrift),api.behaviorRankings().then(setBehavior),
        ]);
      }while(refreshQueued.current);
    }finally{refreshInFlight.current=false}
  },[]);
  const load=useCallback(()=>{void refreshRuntime();api.notifications().then(result=>setNotifications(result.notifications)).catch(()=>{});api.modelStatus().then(setModelStatus).catch(()=>{})},[refreshRuntime]);
  useEffect(()=>{api.me().then(setUser).catch(()=>{}).finally(()=>setAuthReady(true))},[]);
  useEffect(()=>{if(user){load();api.model().then(setModel).catch(()=>{});api.events().then(setLiveEvents).catch(()=>{})}},[load,user]);
  useEffect(()=>{document.documentElement.dataset.theme=theme;localStorage.setItem('deviance-clean-theme',theme)},[theme]);
  useEffect(()=>localStorage.setItem(COLLAPSE_KEY,String(collapsed)),[collapsed]);
  const onStream=useCallback((message:StreamMessage)=>{if(message.type==='scored_event'){setLiveEvents(current=>[message.data,...current.filter(item=>item.event_id!==message.data.event_id)].slice(0,250));void refreshRuntime()}else if(message.type==='simulation_status'){api.notifications().then(result=>setNotifications(result.notifications)).catch(()=>{});if(['completed','stopped','failed'].includes(message.data?.status))void refreshRuntime()}},[refreshRuntime]);
  const onStreamState=useCallback((state:StreamState)=>setConnection(state),[]);
  useLive(onStream,onStreamState,!!user);
  const select=useCallback((alert:Alert)=>{setPage('investigation');setDetail(null);api.alert(alert.id).then(setDetail)},[]);
  const update=useCallback((status:string)=>detail&&api.updateAlert(detail.id,status).then(()=>api.alert(detail.id).then(setDetail).then(load)),[detail,load]);
  const reviewDrift=useCallback(async(id:number,action:DriftReviewAction,comment:string)=>{await api.reviewDrift(id,action,comment);setDrift(await api.drift());api.notifications().then(result=>setNotifications(result.notifications)).catch(()=>{})},[]);
  const openProfile=(userId:string)=>{setSelectedUser(userId);setPage('users')};
  const unread=useMemo(()=>notifications.filter(item=>!readIds.has(item.id)).length,[notifications,readIds]);
  const markRead=(id:string)=>setReadIds(current=>{const next=new Set(current).add(id);localStorage.setItem(READ_KEY,JSON.stringify([...next]));return next});
  const openNotification=(item:AppNotification)=>{setNotificationsOpen(false);if(item.alert_id){const alert=alerts.find(row=>row.id===item.alert_id);if(alert)select(alert);else api.alert(item.alert_id).then(value=>{setDetail(value);setPage('investigation')})}else setPage(item.page)};
  if(!authReady)return <div className="auth-loading"><img src="/deviance-mark.svg" alt=""/><b>DEVIANCE</b></div>;
  if(!user)return <Login onAuthenticated={setUser}/>;
  const logout=()=>{api.logout();setUser(null);setMetrics(null);setAlerts([]);setLiveEvents([])};
  return <div className={`app-frame ${collapsed?'sidebar-collapsed':''}`}><aside className="sidebar"><button className="brand" onClick={()=>setPage('overview')}><img src="/deviance-mark.svg" alt="Deviance"/><strong>deviance</strong></button><nav>{navigation.map(([id,Icon,label])=><button title={collapsed?label:undefined} key={id} className={page===id?'active':''} onClick={()=>setPage(id as Page)}><Icon/><span>{label}</span>{id==='alerts'&&metrics?.unresolved_alerts?<em>{metrics.unresolved_alerts}</em>:null}</button>)}</nav>
    <div className="model-status-anchor"><button className="sidebar-status" onClick={()=>setModelOpen(!modelOpen)}><span><i/> <b>Model online</b></span><small>{model?.model_version||'Awaiting model'}</small></button>{modelOpen&&<ModelStatusPopover status={modelStatus}/>}</div><button className="collapse-control" onClick={()=>setCollapsed(!collapsed)} aria-label={collapsed?'Expand sidebar':'Collapse sidebar'}>{collapsed?<ChevronsRight/>:<ChevronsLeft/>}</button></aside>
    <section className="workspace"><header className="workspace-header"><div><h1>{pageLabels[page]}</h1><span className="active-pill"><i/> Active</span><ChevronDown/></div><div className="header-actions"><button className="icon-button" onClick={()=>setHelpOpen(true)} title="Help"><CircleHelp/></button><div className="notification-anchor"><button className="icon-button notification" onClick={()=>setNotificationsOpen(!notificationsOpen)} title="Notifications"><Bell/>{unread>0&&<i/>}</button>{notificationsOpen&&<NotificationsPopover items={notifications} read={readIds} onRead={markRead} onOpen={openNotification}/>}</div><button className="theme-button" onClick={()=>setTheme(theme==='light'?'dark':'light')}>{theme==='light'?<Moon/>:<Sun/>}<span>{theme==='light'?'Black':'Light'}</span></button><div className="profile"><span>AD</span><div><b>{user.username}</b><small>Administrator</small></div></div><button className="icon-button logout-button" onClick={logout} title="Sign out"><LogOut/></button></div></header>
      <main>{page==='overview'&&<Overview metrics={metrics} model={model} liveEvents={liveEvents} connection={connection}/>} {page==='alerts'&&<Alerts alerts={alerts} onSelect={select}/>} {page==='investigation'&&<Investigation detail={detail} onBack={()=>setPage('alerts')} onUpdate={update} onViewProfile={openProfile}/>} {page==='model'&&<ModelPage model={model}/>} {page==='drift'&&<DriftPage drift={drift} onReview={reviewDrift}/>} {page==='behavior'&&<BehaviorPage behavior={behavior} onViewProfile={openProfile}/>} {page==='users'&&<UsersPage key={selectedUser||'default-profile'} initialUser={selectedUser}/>}</main></section>{helpOpen&&<HelpDrawer onClose={()=>setHelpOpen(false)}/>}</div>;
}
