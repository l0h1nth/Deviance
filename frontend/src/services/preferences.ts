export const ALL_COLUMNS=['time','identity','entity_type','device','detection','risk','anomaly_score','sequence_score','confidence','incident_events','status','location','baseline_type','model_version'] as const;
export type ColumnKey=typeof ALL_COLUMNS[number];
export const DEFAULT_COLUMNS:ColumnKey[]=['time','identity','entity_type','detection','risk','sequence_score','incident_events','status'];
export type SortOrder='risk'|'newest'|'oldest';
export type SavedView={id:string;name:string;search:string;severity:string;visibleColumns:ColumnKey[];sortOrder:SortOrder;predicate?:'unresolved'|'false_positive'|'low_confidence'|'impossible_travel'|'investigating'};
type StorageLike={getItem:(key:string)=>string|null;setItem:(key:string,value:string)=>void};
const COLUMNS_KEY='deviance-visible-columns',VIEWS_KEY='deviance-saved-views';

export const DEFAULT_VIEWS:SavedView[]=[
  {id:'critical-unresolved',name:'Critical unresolved',search:'',severity:'critical',visibleColumns:DEFAULT_COLUMNS,sortOrder:'risk',predicate:'unresolved'},
  {id:'false-positives',name:'False positives',search:'',severity:'all',visibleColumns:DEFAULT_COLUMNS,sortOrder:'newest',predicate:'false_positive'},
  {id:'low-confidence',name:'Low confidence',search:'',severity:'all',visibleColumns:DEFAULT_COLUMNS,sortOrder:'risk',predicate:'low_confidence'},
  {id:'impossible-travel',name:'Impossible travel',search:'impossible travel',severity:'all',visibleColumns:DEFAULT_COLUMNS,sortOrder:'newest',predicate:'impossible_travel'},
  {id:'recent-investigations',name:'Recent investigations',search:'',severity:'all',visibleColumns:DEFAULT_COLUMNS,sortOrder:'newest',predicate:'investigating'},
];

const defaultStorage=():StorageLike|undefined=>typeof localStorage==='undefined'?undefined:localStorage;
export function loadColumns(storage=defaultStorage()):ColumnKey[]{
  try{const parsed=JSON.parse(storage?.getItem(COLUMNS_KEY)||'null');return Array.isArray(parsed)?parsed.filter((value):value is ColumnKey=>ALL_COLUMNS.includes(value)):DEFAULT_COLUMNS}catch{return DEFAULT_COLUMNS}
}
export function saveColumns(columns:ColumnKey[],storage=defaultStorage()){storage?.setItem(COLUMNS_KEY,JSON.stringify(columns))}
export function loadViews(storage=defaultStorage()):SavedView[]{
  try{const parsed=JSON.parse(storage?.getItem(VIEWS_KEY)||'null');return Array.isArray(parsed)?[...DEFAULT_VIEWS,...parsed]:DEFAULT_VIEWS}catch{return DEFAULT_VIEWS}
}
export function saveCustomView(view:SavedView,storage=defaultStorage()){
  const custom=loadViews(storage).filter(item=>!DEFAULT_VIEWS.some(base=>base.id===item.id)&&item.id!==view.id);
  storage?.setItem(VIEWS_KEY,JSON.stringify([...custom,view]));
}
