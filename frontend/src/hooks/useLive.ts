import {useEffect} from 'react';import {streamUrl} from '../services/api';
export function useLive(onEvent:()=>void){useEffect(()=>{const source=new EventSource(streamUrl());source.onmessage=()=>onEvent();return()=>source.close()},[onEvent])}

