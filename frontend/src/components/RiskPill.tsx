export const RISK_TOOLTIP='Risk estimates overall danger using anomaly score, classifier output, behavioral deviation and resource criticality. Confidence measures certainty about the predicted attack class.';
export function RiskPill({score,severity}:{score:number;severity:string}){return <span className={`risk ${severity}`} title={RISK_TOOLTIP}><i/>{Math.round(score)} · {severity}</span>}
