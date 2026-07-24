import {useEffect} from 'react';import {streamUrl} from '../services/api';
export function useLive(onEvent:()=>void,enabled=true){useEffect(()=>{if(!enabled)return;const source=new EventSource(streamUrl());source.onmessage=()=>onEvent();return()=>source.close()},[onEvent,enabled])}

