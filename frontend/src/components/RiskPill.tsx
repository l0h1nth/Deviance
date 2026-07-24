export function RiskPill({score,severity}:{score:number;severity:string}){return <span className={`risk ${severity}`}><i/>{Math.round(score)} · {severity}</span>}

