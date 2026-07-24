import type {ReactNode} from 'react';

export function StatCard({label,value,detail,icon,tone='neutral'}:{label:string;value:string|number;detail?:string;icon:ReactNode;tone?:'neutral'|'danger'|'warning'|'good'}){
  return <article className={`stat ${tone}`}><div className="stat-top"><span>{label}</span>{icon}</div><strong>{value}</strong>{detail&&<small>{detail}</small>}</article>;
}

