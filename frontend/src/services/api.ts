import type {Alert,AlertDetail,AppNotification,DriftResponse,DriftReviewAction,LiveEvent,Metrics,SimulationStatus} from '../types';

const BASE=import.meta.env.VITE_API_URL||'/api';
const TOKEN_KEY='deviance-admin-token';
export type AuthUser={username:string;role:string;display_name:string};

export const authToken=()=>localStorage.getItem(TOKEN_KEY);
async function request<T>(path:string,options?:RequestInit):Promise<T>{
  const token=authToken();
  const response=await fetch(`${BASE}${path}`,{...options,headers:{'Content-Type':'application/json',...(token?{Authorization:`Bearer ${token}`}:{ }),...(options?.headers||{})}});
  if(!response.ok){let detail=response.statusText;try{detail=(await response.json()).detail||detail}catch{}if(response.status===401&&path!='/auth/login')localStorage.removeItem(TOKEN_KEY);throw new Error(detail)}
  return response.json();
}

export const api={
  login:async(username:string,password:string)=>{const result=await request<{access_token:string;user:AuthUser}>('/auth/login',{method:'POST',body:JSON.stringify({username,password})});localStorage.setItem(TOKEN_KEY,result.access_token);return result.user},
  logout:()=>localStorage.removeItem(TOKEN_KEY),
  me:()=>request<AuthUser>('/auth/me'),
  metrics:()=>request<Metrics>('/metrics/overview'),alerts:()=>request<Alert[]>('/alerts?limit=500'),alert:(id:number)=>request<AlertDetail>(`/alerts/${id}`),
  events:(limit=100)=>request<LiveEvent[]>(`/events?limit=${limit}`),latestEvent:()=>request<LiveEvent|null>('/events/latest'),
  model:()=>request<any>('/metrics/model'),modelStatus:()=>request<any>('/models/status'),drift:()=>request<DriftResponse>('/drift'),
  reviewDrift:(id:number,action:DriftReviewAction,comment='')=>request(`/drift/${id}`,{method:'PATCH',body:JSON.stringify({action,comment})}),
  users:(search='')=>request<any[]>(`/users?search=${encodeURIComponent(search)}&limit=20`),
  profile:(id:string)=>request<any>(`/users/${id}/profile`),timeline:(id:string)=>request<any[]>(`/users/${id}/timeline?limit=20`),
  updateAlert:(id:number,status:string,comment='Updated from investigation workspace')=>request(`/alerts/${id}`,{method:'PATCH',body:JSON.stringify({status,analyst:'admin',comment})}),
  startSimulation:(scenario:string,interval_ms:number,event_count:number)=>request<SimulationStatus>('/simulations/start',{method:'POST',body:JSON.stringify({scenario,interval_ms,event_count})}),
  simulationStatus:()=>request<SimulationStatus>('/simulations/status'),stopSimulation:()=>request<SimulationStatus>('/simulations/stop',{method:'POST'}),
  notifications:()=>request<{notifications:AppNotification[]}>('/notifications'),
};
export const streamUrl=()=>`${BASE}/events/stream?token=${encodeURIComponent(authToken()||'')}`;
