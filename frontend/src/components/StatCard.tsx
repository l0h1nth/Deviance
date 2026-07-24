import type {ReactNode} from 'react';
export function StatCard({label,value,detail,icon}:{label:string;value:string|number;detail?:string;icon:ReactNode}){return <article className="stat"><div className="stat-icon">{icon}</div><div><span>{label}</span><strong>{value}</strong>{detail&&<small>{detail}</small>}</div></article>}

