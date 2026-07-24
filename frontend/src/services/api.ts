import type {Alert,AlertDetail,Metrics} from '../types';
const BASE=import.meta.env.VITE_API_URL||'/api';
async function request<T>(path:string,options?:RequestInit):Promise<T>{const response=await fetch(`${BASE}${path}`,{...options,headers:{'Content-Type':'application/json',...(options?.headers||{})}});if(!response.ok)throw new Error((await response.json()).detail||response.statusText);return response.json()}
export const api={metrics:()=>request<Metrics>('/metrics/overview'),alerts:()=>request<Alert[]>('/alerts'),alert:(id:number)=>request<AlertDetail>(`/alerts/${id}`),model:()=>request<any>('/metrics/model'),drift:()=>request<any[]>('/drift'),profile:(id:string)=>request<any>(`/users/${id}/profile`),updateAlert:(id:number,status:string)=>request(`/alerts/${id}`,{method:'PATCH',body:JSON.stringify({status,analyst:'dashboard-analyst',comment:'Updated from investigation workspace'})})};
export const streamUrl=()=>`${BASE}/events/stream`;

