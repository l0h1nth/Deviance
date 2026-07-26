import {Clock,MapPin,Monitor,Search,Server} from 'lucide-react';
import {FormEvent,KeyboardEvent,useEffect,useState} from 'react';
import {api} from '../services/api';

type IdentitySuggestion={user_id:string;display_name?:string;role?:string;department?:string};

export function UsersPage({initialUser}:{initialUser?:string}){
  const[id,setId]=useState(initialUser||''),[profile,setProfile]=useState<any>(null),[timeline,setTimeline]=useState<any[]>([]),[suggestions,setSuggestions]=useState<IdentitySuggestion[]>([]),[error,setError]=useState('');
  const[open,setOpen]=useState(false),[active,setActive]=useState(-1);
  const load=(user:string)=>{setError('');Promise.all([api.profile(user),api.timeline(user)]).then(([p,t])=>{setProfile(p);setTimeline(t)}).catch(()=>setError('No persisted profile for this identity yet. Select another identity or run the stream.'))};
  useEffect(()=>{if(initialUser){setId(initialUser);queueMicrotask(()=>load(initialUser))}},[initialUser]);
  useEffect(()=>{
    let cancelled=false;
    const timer=setTimeout(()=>api.users(id.trim()).then(users=>{if(!cancelled)setSuggestions(users)}).catch(()=>{if(!cancelled)setSuggestions([])}),180);
    return()=>{cancelled=true;clearTimeout(timer)};
  },[id]);
  const choose=(user:IdentitySuggestion)=>{setId(user.user_id);setOpen(false);setActive(-1);load(user.user_id)};
  const submit=(event:FormEvent)=>{event.preventDefault();const user=id.trim();if(!user){setError('Select an identity first.');setOpen(true);return}setOpen(false);load(user)};
  const navigate=(event:KeyboardEvent<HTMLInputElement>)=>{
    if(event.key==='Escape'){setOpen(false);setActive(-1);return}
    if(!suggestions.length)return;
    if(event.key==='ArrowDown'){event.preventDefault();setOpen(true);setActive(current=>current>=suggestions.length-1?0:current+1)}
    if(event.key==='ArrowUp'){event.preventDefault();setOpen(true);setActive(current=>current<=0?suggestions.length-1:current-1)}
    if(event.key==='Enter'&&open&&active>=0){event.preventDefault();choose(suggestions[active])}
  };
  return <><header className="page-head"><div><span className="eyebrow">IDENTITY BASELINES</span><h1>User behavior</h1><p>Inspect trusted norms, cold-start fallback, and recent risk.</p></div></header>
    <div className="identity-search">
      <form className="user-search" onSubmit={submit}><Search/><input value={id} onChange={event=>{setId(event.target.value);setOpen(true);setActive(-1)}} onFocus={()=>setOpen(true)} onBlur={()=>setTimeout(()=>setOpen(false),100)} onKeyDown={navigate} placeholder="Search identity (e.g. usr-000), role, or department" role="combobox" aria-autocomplete="list" aria-expanded={open} aria-controls="identity-options" aria-activedescendant={active>=0?`identity-option-${active}`:undefined}/><button disabled={!id.trim()}>View behavior profile</button></form>
      {open&&<div className="identity-suggestions" id="identity-options" role="listbox">{suggestions.length?suggestions.map((user,index)=><button type="button" id={`identity-option-${index}`} role="option" aria-selected={active===index} className={active===index?'active':''} key={user.user_id} onMouseDown={event=>event.preventDefault()} onClick={()=>choose(user)} onMouseEnter={()=>setActive(index)}><span><strong>{user.user_id}</strong>{user.display_name&&<small>{user.display_name}</small>}</span><em>{[user.role,user.department].filter(Boolean).join(' · ')||'Identity profile'}</em></button>):<div className="identity-suggestion-empty">No matching identities found</div>}</div>}
    </div>
    {error&&<section className="panel empty">{error}</section>}
    {profile&&<><section className="profile-hero panel"><div><span className="eyebrow">{profile.cold_start?'COLD START · PEER/GLOBAL FALLBACK':'MATURE PROFILE'}</span><h2>{profile.display_name} <small>{profile.user_id}</small></h2><p>{profile.role} · {profile.department} · {profile.baseline_type} baseline · {profile.trusted_event_count} trusted events · version {profile.profile_version}</p>{profile.cold_start&&<div className="cold-start-note">This user has insufficient trusted history. Peer or global behavior is being used as the baseline.</div>}</div><strong>{Math.round(profile.confidence*100)}<small>% confidence</small></strong></section>
      <section className="profile-grid"><ProfileCard icon={<Clock/>} title="Normal login" value={`${profile.normal_login_hours.mean.toFixed(1)}h ± ${profile.normal_login_hours.std.toFixed(1)}`}/><ProfileCard icon={<Monitor/>} title="Known devices" value={profile.known_devices.length} detail={profile.known_devices.slice(0,3).join(', ')||'Building trusted history'}/><ProfileCard icon={<MapPin/>} title="Common locations" value={profile.common_locations.length} detail={profile.common_locations.slice(0,2).join(', ')||'Building trusted history'}/><ProfileCard icon={<Server/>} title="Common resources" value={profile.common_resources.length} detail={profile.common_resources.slice(0,3).join(', ')||'Building trusted history'}/></section>
      <section className="panel"><div className="panel-title"><div><span>RISK HISTORY</span><h2>Recent activity</h2></div></div><div className="mini-timeline activity-header"><div><i/><span>Timestamp</span><b>Event</b><em>Prediction</em><strong>Risk</strong></div></div><div className="mini-timeline">{timeline.slice(0,10).map((row,index)=><div key={index}><i className={(row.risk_score||0)>=50?'hot':''}/><span>{new Date(row.event.timestamp).toLocaleString()}</span><b>{row.event.event_type?.replaceAll('_',' ')}</b><em>{row.predicted_attack?.replaceAll('_',' ')||'unscored'}</em><strong>{row.risk_score?.toFixed(1)||'—'}</strong></div>)}</div></section></>}
  </>;
}
function ProfileCard({icon,title,value,detail}:{icon:any;title:string;value:string|number;detail?:string}){return <article className="profile-card"><div>{icon}</div><span>{title}</span><strong>{value}</strong>{detail&&<small>{detail}</small>}</article>}
