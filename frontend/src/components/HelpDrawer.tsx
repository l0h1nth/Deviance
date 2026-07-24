import {X} from 'lucide-react';

const topics=[
  ['Behavioral anomaly detection','Deviance compares each event with trusted user, peer, or organization history. Isolation Forest and the attack classifier remain the primary detectors.'],
  ['Risk score','Overall danger from anomaly evidence, malicious-class probability, behavioral deviation, and resource criticality.'],
  ['Anomaly score','Isolation Forest output measuring how unusual the 24-feature vector is compared with normal-only training data.'],
  ['Sequence score','GRU reconstruction error measuring whether an entity’s current event is unexpected given its preceding event sequence.'],
  ['Classifier confidence','Certainty about the predicted attack class. It is separate from risk and low-confidence predictions remain visible.'],
  ['Cold start','When trusted user history is insufficient, peer or global behavior supplies the baseline with lower confidence.'],
  ['Concept drift','A statistically significant change between trusted reference and current windows. Drift is reviewed; it does not activate a new model.'],
  ['Analyst statuses','Open, Investigating, Confirmed Threat, False Positive, and Closed. Every update is saved in feedback history.'],
  ['Synthetic simulation','Generated multi-event security scenarios flow through the same validation, persistence, ML inference, risk, alert, and SSE path as ingested telemetry.'],
  ['Model limitations','Synthetic evaluation does not establish production efficacy. Rare classes, changing environments, privacy controls, and human review still require real-world validation.'],
];
export function HelpDrawer({onClose}:{onClose:()=>void}){return <div className="drawer-backdrop" onMouseDown={event=>event.target===event.currentTarget&&onClose()}><aside className="help-drawer"><header><div><span className="eyebrow">DEVIANCE GUIDE</span><h2>How detection works</h2></div><button className="icon-button" onClick={onClose}><X/></button></header>{topics.map(([title,body])=><article key={title}><h3>{title}</h3><p>{body}</p></article>)}</aside></div>}
