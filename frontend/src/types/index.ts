export type Page='overview'|'alerts'|'model'|'drift'|'behavior'|'users'|'investigation';

export type Alert = {
  id:number;timestamp:string;entity_id:string;entity_type:string;user_id:string;device_id:string;predicted_attack:string;display_attack:string;
  risk_score:number;severity:string;anomaly_score:number;sequence_anomaly_score:number;classifier_confidence:number;confidence:number;
  status:string;location:string;baseline_type:string;model_version:string;explanation:string;
  incident_key?:string;incident_event_count:number;
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
  holdout_alert_rate:number;top_1_percent_precision:number;top_1_percent_recall:number;alerts_per_10000:number;
  average_inference_latency_ms:number;attacks_by_type:Record<string,number>;risk_trend:{id:number;risk:number}[];
};

export type LiveEvent={
  event_id:string;timestamp:string;entity_id:string;entity_type:string;user_id:string;device_id:string;event_type:string;
  location:{city:string;country:string;latitude?:number;longitude?:number};authentication_result:string;
  predicted_attack:string;display_attack?:string;anomaly_score:number;sequence_anomaly_score:number;classifier_confidence:number;
  behavioral_score:number;domain_anomaly_scores:Record<string,number>;
  class_probabilities:Record<string,number>;risk_score:number;severity:string;latency_ms:number;
  features:Record<string,number>;feature_evidence:FeatureEvidence[];baseline_type:string;baseline_confidence:number;
  model_version:string;feature_schema_version:string;top_contributing_features:FeatureEvidence[];
  risk_composition:Record<string,number>;explanation:string;cold_start:boolean;alert_id?:number|null;
  incident_event_count:number;event:Record<string,any>;
};

export type SimulationStatus={
  status:string;scenario:string|null;interval_ms:number|null;event_count:number;processed_events:number;
  ground_truth_attack_events:number;ground_truth_normal_events:number;detected_attack_events:number;
  missed_attack_events:number;correct_attack_classifications:number;misclassified_attack_events:number;
  false_positive_events:number;new_incident_count:number;alert_count:number;
  started_at:string|null;stopped_at:string|null;telemetry_start:string|null;telemetry_end:string|null;
  last_event_id:string|null;last_error:string|null;
};
export type DriftReviewAction='investigate'|'approve_adaptation'|'reject_change'|'dismiss';
export type DriftEvent={id:number;subject_id:string;feature:string;magnitude:number;recommendation:string;detected_at:string;status:string;review_status:string;severity:string;domain:string;ks_distance:number;absolute_shift:number;baseline_version:number;previous_distribution:Record<string,number>;current_distribution:Record<string,number>;drift_confidence:number;review_history:{action:string;analyst:string;comment:string;created_at:string}[];metadata:Record<string,any>};
export type DriftWindow={entity:string;reference_window:{count:number;target:number};current_window:{count:number;target:number};status:string;trusted_events_only:boolean;flagged_features:string[];baseline_version:number;last_observed_at:string|null};
export type DriftSummary={state:string;pending_reviews:number;approved_adaptations:number;rejected_changes:number;monitored_entities:number;trusted_events:number;signals_monitored:number;reference_size:number;current_size:number;policy:string;automatic_retraining:boolean};
export type DriftResponse={events:DriftEvent[];windows:DriftWindow[];summary?:DriftSummary};
export type BehaviorRanking={rank:number;entity_id:string;rank_score:number;maximum_drift_30d:number;drift_days_30d:number;consecutive_drift_days:number;mean_top_3_drift:number;last_drift_date:string|null;latest_score:number;has_attack:boolean};
export type BehaviorRankings={model_ready:boolean;model_version?:string;threshold:number;window_days:number;minimum_history_days?:number;daily_observations?:number;rankings:BehaviorRanking[]};
export type AppNotification={id:string;type:string;title:string;message:string;created_at:string|null;page:Page;alert_id?:number};
