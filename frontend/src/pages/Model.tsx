const percent=(value:any)=>typeof value==='number'?(value*100).toFixed(1)+'%':'—';
const number=(value:any,digits=1)=>typeof value==='number'?value.toFixed(digits):'—';

export function ModelPage({model}:{model:any}){
  const metrics=model?.metrics||{},test=metrics.test||{},classes=test.classes||[],matrix=test.confusion_matrix||[];
  const selection=metrics.threshold_selection||{},behaviorSelection=metrics.behavioral_threshold_selection||{};
  const population=metrics.training_population||{},classifierSelection=metrics.classifier_selection||{};
  const scenario=test.scenario_detection||{},priority=test.priority_queue||{},cold=test.cold_start_evaluation||{};
  const coldOverall=cold.overall||{},coldBuckets=cold.by_history_bucket||{},coldAttack=cold.attack_challenge||{};
  const coldClasses=coldAttack.by_attack_class||{};
  const cards=[
    ['Classifier accuracy',test.classifier_accuracy,'Correct multiclass predictions divided by all holdout events. Read with Macro F1 because normal events dominate.'],
    ['Classifier Macro F1',test.macro_f1,'Unweighted event-level classification F1 across normal and the six required attack classes.'],
    ['Classifier PR-AUC',test.classifier_pr_auc,'Known-attack probability ranking on the imbalanced untouched holdout.'],
    ['Behavioral PR-AUC',test.behavioral_pr_auc,'Normal-only Isolation Forest, GRU, and profile-deviation ranking without classifier evidence.'],
    ['Behavioral recall',test.behavioral_recall,'Attacks caught using only normal-trained behavioral evidence at its frozen threshold.'],
    ['Finding precision',test.alert_precision,'Precision of operational findings at the recall-oriented validation threshold.'],
    ['Finding recall',test.alert_recall,'Event-level attacks surfaced by the operational finding threshold.'],
    ['Scenario recall',scenario.recall,'Injected multi-event attack scenarios with at least one event surfaced.'],
  ];
  return <>
    <header className="page-head"><div><span className="eyebrow">MODEL GOVERNANCE</span><h1>Performance</h1><p>Entity-disjoint chronological evaluation with normal-only anomaly learning, a held-out classifier choice, and two analyst thresholds.</p></div></header>
    <section className="stats model-stats">{cards.map(([name,value,help])=><article className="metric" key={String(name)} title={String(help)}><span>{name}</span><strong>{percent(value)}</strong><small>{help}</small></article>)}</section>

    <section className="panel model-card"><div className="panel-title"><div><span>COLD-START SAFETY</span><h2>Performance before personal-profile maturity</h2></div><strong>{coldOverall.sample_count??'—'} holdout events</strong></div><dl className="budget-grid">
      <div><dt>Benign cold-start FPR</dt><dd>{percent(coldOverall.benign_false_positive_rate)}</dd></div>
      <div><dt>Cold-start attack recall</dt><dd>{percent(coldAttack.attack_recall)}</dd></div>
      <div><dt>Cold-start scenario recall</dt><dd>{percent(coldAttack.scenario_recall)}</dd></div>
      <div><dt>Behavior-only attack recall</dt><dd>{percent(coldAttack.behavioral_attack_recall)}</dd></div>
      <div><dt>Normal support</dt><dd>{coldOverall.normal_count??'—'}</dd></div>
      <div><dt>Attack challenge support</dt><dd>{coldAttack.event_count??'—'} events · {coldAttack.scenario_count??'—'} scenarios</dd></div>
      <div><dt>Maturity boundary</dt><dd>{cold.maturity_threshold??12} prior events</dd></div>
      <div><dt>Evaluation policy</dt><dd>{cold.profile_update_policy||'Chronological holdout profile updates'}</dd></div>
    </dl>{Object.keys(coldBuckets).length>0&&<><h3>Profile maturity buckets</h3><div className="class-report"><div className="class-report-head"><b>Prior history</b><span>Support</span><span>Benign FPR</span><span>Attack recall</span></div>{Object.entries(coldBuckets).map(([name,value]:any)=><div key={name}><b>{name} events</b><span>{value.sample_count} total · {value.attack_count} attacks</span><span>{percent(value.benign_false_positive_rate)}</span><span>{percent(value.attack_recall)}</span></div>)}</div></>}{Object.keys(coldClasses).length>0&&<><h3>Fresh-identity attack challenge</h3><div className="class-report"><div className="class-report-head"><b>Attack class</b><span>Event support</span><span>Event recall</span><span>Scenario recall</span></div>{Object.entries(coldClasses).map(([name,value]:any)=><div key={name}><b>{name.replaceAll('_',' ')}</b><span>{value.event_support} events · {value.scenario_support} scenarios</span><span>{percent(value.event_recall)}</span><span>{percent(value.scenario_recall)}</span></div>)}</div></>}</section>

    <section className="panel model-card"><h2>Active v3 ensemble</h2><dl>
      <div><dt>Model version</dt><dd>{model?.model_version||'Not trained'}</dd></div>
      <div><dt>Feature contract</dt><dd>{model?.feature_names?.length||0} signals · schema {model?.feature_schema_version||'—'}</dd></div>
      <div><dt>Anomaly layer</dt><dd>{model?.anomaly_model?.type||'Domain Isolation Forest ensemble'} · {(model?.anomaly_model?.domains||[]).length} domains</dd></div>
      <div><dt>Sequence layer</dt><dd>{model?.sequence_model?.type||'GRU sequence detector'} · {model?.sequence_model?.window_size||12} events · top {model?.sequence_model?.error_top_k||5} residuals</dd></div>
      <div><dt>Selected classifier</dt><dd>{model?.classifier?.type?.replaceAll?.('_',' ')||classifierSelection.selected||'—'}</dd></div>
      <div><dt>Selection guard</dt><dd>RF and XGBoost compared on a dedicated validation partition</dd></div>
      <div><dt>Training policy</dt><dd>Scaler, domain IFs, and GRU: normal only · classifier: labeled classes</dd></div>
    </dl></section>

    <section className="panel threshold-card"><div className="panel-title"><div><span>DUAL DECISION POLICY</span><h2>Find broadly, prioritize narrowly</h2></div><strong>{number(model?.alert_threshold)} finding · {number(model?.priority_threshold)} priority</strong></div><dl className="budget-grid">
      <div><dt>Finding selection</dt><dd>{selection.selection_method||'Recall under validation FPR constraint'}</dd></div>
      <div><dt>Validation finding FPR</dt><dd>{percent(selection.validation_false_positive_rate)}</dd></div>
      <div><dt>Holdout finding FPR</dt><dd>{percent(test.alert_false_positive_rate)}</dd></div>
      <div><dt>Insider-drift FPR</dt><dd>{percent(test.insider_drift_false_positive_rate)}</dd></div>
      <div><dt>Holdout findings / 10k</dt><dd>{number(test.alerts_per_10000)}</dd></div>
      <div><dt>Frozen priority precision</dt><dd>{percent(priority.precision)}</dd></div>
      <div><dt>Frozen priority recall</dt><dd>{percent(priority.recall)}</dd></div>
      <div><dt>Behavior-only threshold</dt><dd>{number(model?.behavioral_threshold,3)}</dd></div>
      <div><dt>Behavior validation FPR</dt><dd>{percent(behaviorSelection.validation_false_positive_rate)}</dd></div>
      <div><dt>Test attack prevalence</dt><dd>{percent(test.attack_prevalence)}</dd></div>
    </dl></section>

    <section className="panel model-card"><h2>Leakage and overfitting controls</h2><dl>
      <div><dt>Training rows</dt><dd>{population.total_rows??'—'} total · {population.normal_rows??'—'} normal · {population.attack_rows??'—'} attacks</dd></div>
      <div><dt>Preprocessor fit</dt><dd>{population.preprocessor_fit?.replaceAll('_',' ')||'normal only'}</dd></div>
      <div><dt>Domain Isolation Forest fit</dt><dd>{population.anomaly_detector_fit?.replaceAll('_',' ')||'normal only'}</dd></div>
      <div><dt>GRU fit</dt><dd>{population.sequence_detector_fit?.replaceAll('_',' ')||'normal sequences only'}</dd></div>
      <div><dt>Classifier fit</dt><dd>{population.classifier_fit?.replaceAll('_',' ')||'normal and attacks'}</dd></div>
      <div><dt>Probability calibration</dt><dd>{population.classifier_probability_calibration?.replaceAll('_',' ')||'validation sigmoid'}</dd></div>
      <div><dt>Classifier selection</dt><dd>{classifierSelection.policy||'validation macro F1 with malicious PR-AUC tie-break'}</dd></div>
    </dl></section>

    {test.classification_report&&<section className="panel model-card"><h2>Event classification by class</h2><div className="class-report"><div className="class-report-head"><b>Class</b><span>Precision</span><span>Recall</span><span>F1 / support</span></div>{Object.entries(test.classification_report).filter(([name,value])=>typeof value==='object'&&!['macro avg','weighted avg'].includes(name)).map(([name,value]:any)=><div key={name}><b>{name.replaceAll('_',' ')}</b><span>{percent(value.precision)}</span><span>{percent(value.recall)}</span><span>{percent(value['f1-score'])} · {value.support}</span></div>)}</div></section>}

    {matrix.length>0&&<section className="panel confusion"><div className="panel-title"><div><span>UNTOUCHED HOLDOUT</span><h2>Confusion matrix</h2></div></div><div className="matrix" style={{gridTemplateColumns:`150px repeat(${classes.length}, minmax(85px,1fr))`,minWidth:`${150+classes.length*85}px`}}><div/>{classes.map((className:string)=><b key={className}>{className.replaceAll('_',' ')}</b>)}{matrix.map((row:number[],index:number)=><div className="matrix-row" key={classes[index]}><strong>{classes[index].replaceAll('_',' ')}</strong>{row.map((value,column)=><span className={index===column?'correct':''} key={column}>{value}</span>)}</div>)}</div></section>}
  </>;
}
