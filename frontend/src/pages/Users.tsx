import {Clock,MapPin,Monitor,Search,Server} from 'lucide-react';
import {FormEvent,useEffect,useState} from 'react';
import {api} from '../services/api';

export function UsersPage({initialUser}:{initialUser?:string}){
  const[id,setId]=useState(initialUser||'usr-000'),[profile,setProfile]=useState<any>(null),[timeline,setTimeline]=useState<any[]>([]),[error,setError]=useState('');
  const load=(user:string)=>{setError('');Promise.all([api.profile(user),api.timeline(user)]).then(([p,t])=>{setProfile(p);setTimeline(t)}).catch(()=>setError('No persisted profile for this identity yet. Run the stream or try usr-000.'))};
  useEffect(()=>{if(initialUser)load(initialUser)},[initialUser]);
  const submit=(e:FormEvent)=>{e.preventDefault();load(id)};
  return <><header className="page-head"><div><span className="eyebrow">IDENTITY BASELINES</span><h1>User behavior</h1><p>Inspect trusted norms, cold-start fallback, and recent risk.</p></div></header>
    <form className="user-search" onSubmit={submit}><Search/><input value={id} onChange={e=>setId(e.target.value)} placeholder="Identity, e.g. usr-000"/><button>Load profile</button></form>
    {error&&<section className="panel empty">{error}</section>}
    {profile&&<><section className="profile-hero panel"><div><span className="eyebrow">{profile.cold_start?'COLD START':'MATURE PROFILE'}</span><h2>{profile.user_id}</h2><p>{profile.baseline_type} baseline · {profile.event_count} trusted events · version {profile.profile_version}</p></div><strong>{Math.round(profile.confidence*100)}<small>% confidence</small></strong></section>
      <section className="profile-grid"><ProfileCard icon={<Clock/>} title="Normal login" value={`${profile.normal_login_hours.mean.toFixed(1)}h ± ${profile.normal_login_hours.std.toFixed(1)}`}/><ProfileCard icon={<Monitor/>} title="Known devices" value={profile.known_devices.length} detail={profile.known_devices.slice(0,3).join(', ')||'Building history'}/><ProfileCard icon={<MapPin/>} title="Common locations" value={profile.common_locations.length} detail={profile.common_locations.slice(0,2).join(', ')||'Building history'}/><ProfileCard icon={<Server/>} title="Common resources" value={profile.common_resources.length} detail={profile.common_resources.slice(0,3).join(', ')||'Building history'}/></section>
      <section className="panel"><div className="panel-title"><div><span>RISK HISTORY</span><h2>Recent activity</h2></div></div><div className="mini-timeline">{timeline.slice(0,10).map((row,i)=><div key={i}><i className={(row.risk_score||0)>=50?'hot':''}/><span>{new Date(row.event.timestamp).toLocaleString()}</span><b>{row.event.event_type?.replaceAll('_',' ')}</b><em>{row.predicted_attack?.replaceAll('_',' ')||'unscored'}</em><strong>{row.risk_score?.toFixed(1)||'—'}</strong></div>)}</div></section></>}
  </>;
}

function ProfileCard({icon,title,value,detail}:{icon:any;title:string;value:string|number;detail?:string}){return <article className="profile-card"><div>{icon}</div><span>{title}</span><strong>{value}</strong>{detail&&<small>{detail}</small>}</article>}
