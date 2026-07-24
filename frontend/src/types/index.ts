export type Page='overview'|'alerts'|'model'|'drift'|'users'|'investigation';

export type Alert = {
  id:number;timestamp:string;user_id:string;device_id:string;predicted_attack:string;display_attack:string;
  risk_score:number;severity:string;anomaly_score:number;classifier_confidence:number;confidence:number;
  status:string;location:string;baseline_type:string;model_version:string;explanation:string;
};

export type FeatureEvidence={feature:string;value:number;baseline:number;deviation:number;description:string};
export type TimelineEntry={event:Record<string,any>;prediction:{anomaly_score:number;classifier_confidence:number;predicted_attack:string;risk_score:number;severity:string}|null};
export type AlertDetail = Alert & {
  event:Record<string,any>;features:Record<string,number>;class_probabilities:Record<string,number>;
  baseline_confidence:number;feature_schema_version:string;cold_start:boolean;
  feature_evidence:FeatureEvidence[];risk_composition:Record<string,number>;recommended_actions:string[];
  explanation_detail:{text:string;recommended_actions:string[];risk_composition:Record<string,number>;feature_evidence:FeatureEvidence[];top_contributing_features:{feature:string;value:number;expected:number;deviation:number;description:string}[]};
  feedback:{status:string;analyst:string;comment:string;created_at:string}[];timeline:TimelineEntry[];
};

export type Metrics = {
  events_analyzed:number;total_alerts:number;unresolved_alerts:number;open_alerts:number;
  investigating_alerts:number;reviewed_alerts:number;critical_alerts:number;
  analyst_false_positive_rate_24h:number;holdout_false_positive_rate:number;
  average_inference_latency_ms:number;attacks_by_type:Record<string,number>;risk_trend:{id:number;risk:number}[];
};

export type LiveEvent={
  event_id:string;timestamp:string;user_id:string;device_id:string;event_type:string;
  location:{city:string;country:string;latitude?:number;longitude?:number};authentication_result:string;
  predicted_attack:string;display_attack?:string;anomaly_score:number;classifier_confidence:number;
  class_probabilities:Record<string,number>;risk_score:number;severity:string;latency_ms:number;
  features:Record<string,number>;feature_evidence:FeatureEvidence[];baseline_type:string;baseline_confidence:number;
  model_version:string;feature_schema_version:string;top_contributing_features:FeatureEvidence[];
  risk_composition:Record<string,number>;explanation:string;cold_start:boolean;alert_id?:number|null;
  event:Record<string,any>;
};

export type SimulationStatus={status:string;scenario:string|null;interval_ms:number|null;event_count:number;processed_events:number;alert_count:number;started_at:string|null;stopped_at:string|null;last_event_id:string|null;last_error:string|null};
export type DriftEvent={id:number;subject_id:string;feature:string;magnitude:number;recommendation:string;detected_at:string;status:string;review_status:string;previous_distribution:Record<string,number>;current_distribution:Record<string,number>;drift_confidence:number;metadata:Record<string,any>};
export type DriftResponse={events:DriftEvent[];windows:{entity:string;reference_window:{count:number;target:number};current_window:{count:number;target:number};status:string;trusted_events_only:boolean}[]};
export type AppNotification={id:string;type:string;title:string;message:string;created_at:string|null;page:Page;alert_id?:number};
