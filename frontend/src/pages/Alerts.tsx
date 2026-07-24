import {Filter,Search,SlidersHorizontal,X} from 'lucide-react';
import {useEffect,useMemo,useState} from 'react';
import {AlertTable} from '../components/AlertTable';
import type {Alert} from '../types';
import {ALL_COLUMNS,loadColumns,loadViews,saveColumns,saveCustomView,type ColumnKey,type SavedView,type SortOrder} from '../services/preferences';

export function Alerts({alerts,onSelect}:{alerts:Alert[];onSelect:(a:Alert)=>void}){
  const[q,setQ]=useState(''),[severity,setSeverity]=useState('all'),[columns,setColumns]=useState<ColumnKey[]>(loadColumns),[sort,setSort]=useState<SortOrder>('risk');
  const[predicate,setPredicate]=useState<SavedView['predicate']>(),[columnsOpen,setColumnsOpen]=useState(false),[viewsOpen,setViewsOpen]=useState(false),[viewName,setViewName]=useState('');
  useEffect(()=>saveColumns(columns),[columns]);
  const views=loadViews();
  const shown=useMemo(()=>alerts.filter(alert=>{
    const matchesSeverity=severity==='all'||alert.severity===severity;
    const matchesSearch=JSON.stringify(alert).toLowerCase().replaceAll('_',' ').includes(q.toLowerCase());
    const matchesPredicate=!predicate||predicate==='unresolved'&&['open','investigating','confirmed_threat'].includes(alert.status)||predicate==='false_positive'&&alert.status==='false_positive'||predicate==='low_confidence'&&alert.classifier_confidence<.6||predicate==='impossible_travel'&&alert.predicted_attack==='impossible_travel'||predicate==='investigating'&&alert.status==='investigating';
    return matchesSeverity&&matchesSearch&&matchesPredicate;
  }).sort((a,b)=>sort==='risk'?b.risk_score-a.risk_score||(b.incident_event_count||1)-(a.incident_event_count||1):(sort==='newest'?-1:1)*(new Date(a.timestamp).getTime()-new Date(b.timestamp).getTime())),[alerts,q,severity,predicate,sort]);
  const toggleColumn=(column:ColumnKey)=>setColumns(current=>current.includes(column)?current.length>1?current.filter(item=>item!==column):current:[...current,column]);
  const applyView=(view:SavedView)=>{setQ(view.search);setSeverity(view.severity);setColumns(view.visibleColumns);setSort(view.sortOrder);setPredicate(view.predicate);setViewsOpen(false)};
  const saveView=()=>{if(!viewName.trim())return;saveCustomView({id:`custom-${Date.now()}`,name:viewName.trim(),search:q,severity,visibleColumns:columns,sortOrder:sort,predicate});setViewName('');setViewsOpen(false)};
  return <><header className="page-head"><div><span className="eyebrow">DETECTION MANAGEMENT</span><h1>Detection queue</h1><p>Prioritize, investigate, and disposition model-generated behavioral findings.</p></div><div className="page-controls popover-anchor"><button onClick={()=>{setColumnsOpen(!columnsOpen);setViewsOpen(false)}}><SlidersHorizontal/> Edit columns</button><button onClick={()=>{setViewsOpen(!viewsOpen);setColumnsOpen(false)}}><Filter/> Saved views</button>
    {columnsOpen&&<section className="control-popover columns-popover"><header><b>Visible columns</b><button onClick={()=>setColumnsOpen(false)}><X/></button></header>{ALL_COLUMNS.map(column=><label key={column}><input type="checkbox" checked={columns.includes(column)} onChange={()=>toggleColumn(column)}/>{column.replaceAll('_',' ')}</label>)}</section>}
    {viewsOpen&&<section className="control-popover views-popover"><header><b>Saved views</b><button onClick={()=>setViewsOpen(false)}><X/></button></header>{views.map(view=><button className="saved-view" key={view.id} onClick={()=>applyView(view)}><span>{view.name}</span><small>{view.severity} · {view.sortOrder}</small></button>)}<div className="save-view"><input placeholder="New view name" value={viewName} onChange={event=>setViewName(event.target.value)}/><button onClick={saveView}>Save current</button></div></section>}</div></header>
    <section className="queue-toolbar"><div className="search"><Search/><input placeholder="Search entity, host, detection, status…" value={q} onChange={event=>{setQ(event.target.value);setPredicate(undefined)}}/><kbd>/</kbd></div><div className="severity-tabs">{['all','critical','high','medium','low'].map(value=><button className={severity===value?'active':''} onClick={()=>{setSeverity(value);setPredicate(undefined)}} key={value}>{value}<span>{value==='all'?alerts.length:alerts.filter(alert=>alert.severity===value).length}</span></button>)}</div></section>
    <section className="panel alerts full"><div className="queue-count"><b>{shown.length}</b> ranked incidents <button onClick={()=>setSort(sort==='risk'?'newest':sort==='newest'?'oldest':'risk')}>Sorted by {sort} first ↕</button></div><AlertTable alerts={shown} onSelect={onSelect} columns={columns}/></section></>;
}
