import {useEffect} from 'react';
import {streamUrl} from '../services/api';

export type StreamState='connecting'|'connected'|'disconnected';
export type StreamMessage={type:string;data:any};

export function useLive(onEvent:(message:StreamMessage)=>void,onState:(state:StreamState)=>void,enabled=true){
  useEffect(()=>{
    if(!enabled){onState('disconnected');return}
    onState('connecting');
    const source=new EventSource(streamUrl());
    source.onopen=()=>onState('connected');
    source.onerror=()=>onState('disconnected');
    source.onmessage=(event)=>{try{onEvent(JSON.parse(event.data))}catch{/* Ignore malformed stream frames. */}};
    return()=>{source.close();onState('disconnected')};
  },[onEvent,onState,enabled]);
}
