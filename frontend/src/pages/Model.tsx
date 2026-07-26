const percent=(value:any,digits=1)=>typeof value==='number'?(value*100).toFixed(digits)+'%':'—';
const number=(value:any,digits=1)=>typeof value==='number'?value.toFixed(digits):'—';
const barWidth=(value:any)=>`${Math.max(0,Math.min(100,(typeof value==='number'?value:0)*100))}%`;

export function ModelPage({model}:{model:any}){
  const metrics=model?.metrics||{},test=metrics.audit||metrics.test||{},classes=test.classes||[],matrix=test.confusion_matrix||[];
  const selection=metrics.threshold_selection||{},behaviorSelection=metrics.behavioral_threshold_selection||{};
  const population=metrics.training_population||{},classifierSelection=metrics.classifier_selection||{};
  const sequenceComparison=metrics.event_sequence_comparison||{},entityBehavior=metrics.entity_behavior?.audit||metrics.entity_behavior?.test||{};
  const priority=test.priority_queue||{},topOne=test.top_1_percent||priority,cold=test.cold_start_evaluation||{};
  const normalSupport=test.classification_report?.normal?.support||0;
  const topOneFpr=typeof topOne.false_positive_rate==='number'?topOne.false_positive_rate:(topOne.false_positives||0)/Math.max(normalSupport,1);
  const coldOverall=cold.overall||{},coldBuckets=cold.by_history_bucket||{},coldAttack=cold.attack_challenge||{};
  const coldClasses=coldAttack.by_attack_class||{};
  const coldFalsePositives=Math.round((coldOverall.normal_count||0)*(coldOverall.benign_false_positive_rate||0));
  const coldCaught=Math.round((coldAttack.event_count||0)*(coldAttack.attack_recall||0));
  const coldScenarios=Math.round((coldAttack.scenario_count||0)*(coldAttack.scenario_recall||0));
  const cards:[string,any,string,number?][]=[
    ['Detection accuracy',test.classifier_accuracy,'Correct predictions on the entity-disjoint imbalanced holdout. Read with attack-type Macro F1 because normal events dominate.'],
    ['Attack-type Macro F1',test.macro_f1,'Unweighted classification quality across normal and all six required anomaly types.'],
    ['Finding precision',test.alert_precision,'True attack events divided by all events surfaced at the operational finding threshold.'],
    ['Finding recall',test.alert_recall,'Attack events surfaced at the recall-oriented operational finding threshold.'],
    ['Finding false-positive rate',test.alert_false_positive_rate,'Normal holdout events incorrectly surfaced at the operational finding threshold.',2],
    ['Top 1% precision',topOne.precision,'Attack precision among the highest-risk one percent of holdout events.'],
    ['Top 1% recall',topOne.recall,'Share of all holdout attack events captured within the one-percent analyst budget.'],
    ['Top 1% false-positive rate',topOneFpr,'Normal holdout events incorrectly included in the highest-risk one-percent analyst queue.',2],
  ];
  return <>
    <header className="page-head"><div><span className="eyebrow">MODEL GOVERNANCE</span><h1>Performance</h1><p>Independent-seed, entity-disjoint chronological audit after normal-only anomaly learning and frozen validation thresholds.</p></div></header>
    <section className="stats model-stats">{cards.map(([name,value,help,digits])=><article className="metric" key={name} title={help}><span>{name}</span><strong>{percent(value,digits)}</strong><small>{help}</small></article>)}</section>

    <section className="panel cold-start-card">
      <header className="cold-start-head"><div><span className="eyebrow">COLD-START SAFETY</span><h2>New identities, measured honestly</h2><p>Peer and global behavior protect an entity until its personal profile becomes mature.</p></div><span className="cold-start-badge"><i/>Fallback active · &lt; {cold.maturity_threshold??12} events</span></header>
      <div className="cold-kpi-grid">
        <article className="safe"><span>Benign FPR</span><strong>{percent(coldOverall.benign_false_positive_rate)}</strong><small>{coldFalsePositives} of {coldOverall.normal_count??'—'} normal events alerted</small></article>
        <article><span>Attack recall</span><strong>{percent(coldAttack.attack_recall)}</strong><small>{coldCaught} of {coldAttack.event_count??'—'} fresh-identity attacks surfaced</small></article>
        <article><span>Scenario coverage</span><strong>{percent(coldAttack.scenario_recall)}</strong><small>{coldScenarios} of {coldAttack.scenario_count??'—'} complete scenarios found</small></article>
        <article><span>Behavior only</span><strong>{percent(coldAttack.behavioral_attack_recall)}</strong><small>IF + GRU + profile deviation, no classifier</small></article>
      </div>
      <div className="cold-context-strip"><span><b>{cold.maturity_threshold??12}</b> trusted events to mature</span><span><b>Peer → global</b> fallback order</span><span><b>3 events</b> before GRU activates</span><span><b>{coldOverall.sample_count??'—'}</b> chronological holdout events</span></div>
      <div className="cold-detail-grid">
        <article className="cold-subcard"><header><div><span>PROFILE MATURITY</span><h3>Benign alert pressure</h3></div><small>Lower is better</small></header><div className="maturity-list">{Object.entries(coldBuckets).map(([name,value]:any)=><div key={name}><span><i className={value.benign_false_positive_rate<=.01?'good':'warn'}/><b>{name} prior events</b><small>{value.normal_count} normal samples</small></span><strong>{percent(value.benign_false_positive_rate)}<small>FPR</small></strong></div>)}</div></article>
        <article className="cold-subcard"><header><div><span>FRESH-IDENTITY CHALLENGE</span><h3>Coverage by attack class</h3></div><small>Event recall · scenario recall</small></header><div className="cold-coverage-list">{Object.entries(coldClasses).map(([name,value]:any)=><div key={name}><div><span><b>{name.replaceAll('_',' ')}</b><small>{value.event_support} events · {value.scenario_support} scenarios</small></span><strong>{percent(value.event_recall)} <small>{percent(value.scenario_recall)} scenarios</small></strong></div><span className="coverage-track"><i style={{width:barWidth(value.event_recall)}} className={value.event_recall>=.8?'good':value.event_recall>=.5?'warn':'weak'}/></span></div>)}</div></article>
      </div>
      <footer className="cold-method-note"><span>Evaluation contract</span><p>Unseen identities use training-only peer/global priors. Attack challenge events never update their own profiles.</p></footer>
    </section>

    <section className="panel model-card"><h2>Active v3 ensemble</h2><dl>
      <div><dt>Model version</dt><dd>{model?.model_version||'Not trained'}</dd></div>
      <div><dt>Feature contract</dt><dd>{model?.feature_names?.length||0} event inputs · {model?.enriched_feature_names?.length||0} daily inputs · schema {model?.feature_schema_version||'—'}</dd></div>
      <div><dt>Anomaly layer</dt><dd>{model?.anomaly_model?.type||'Domain Isolation Forest ensemble'} · {(model?.anomaly_model?.domains||[]).length} domains</dd></div>
      <div><dt>Event sequence layer</dt><dd>{model?.sequence_model?.type||'GRU sequence detector'} · {model?.sequence_model?.source_input_size||model?.feature_names?.length||32} inputs · {model?.sequence_model?.window_size||12} events</dd></div>
      <div><dt>Daily behavior layer</dt><dd>{model?.entity_behavior_model?`${model.entity_behavior_model.type} · ${model.entity_behavior_model.source_input_size} inputs · ${model.entity_behavior_model.window_size} days`:'Not available'}</dd></div>
      <div><dt>Selected classifier</dt><dd>{model?.classifier?.type?.replaceAll?.('_',' ')||classifierSelection.selected||'—'}</dd></div>
      <div><dt>Selection guard</dt><dd>RF and XGBoost compared on a dedicated validation partition</dd></div>
      <div><dt>Training policy</dt><dd>Scaler, domain IFs, and GRU: normal only · classifier: labeled classes</dd></div>
    </dl></section>

    {sequenceComparison.rejected_42_feature_gru&&<section className="panel threshold-card"><div className="panel-title"><div><span>BEHAVIORAL-DRIFT EXPERIMENT</span><h2>Held-out architecture comparison</h2></div><strong>32-input event path selected</strong></div><dl className="budget-grid">
      <div><dt>Active 32-input GRU PR-AUC</dt><dd>{percent(sequenceComparison.active_32_feature_gru?.pr_auc)}</dd></div>
      <div><dt>Rejected 42-input GRU PR-AUC</dt><dd>{percent(sequenceComparison.rejected_42_feature_gru?.pr_auc)}</dd></div>
      <div><dt>Active GRU ROC-AUC</dt><dd>{percent(sequenceComparison.active_32_feature_gru?.roc_auc)}</dd></div>
      <div><dt>Rejected GRU ROC-AUC</dt><dd>{percent(sequenceComparison.rejected_42_feature_gru?.roc_auc)}</dd></div>
      <div><dt>Daily drift PR-AUC</dt><dd>{percent(entityBehavior.pr_auc)}</dd></div>
      <div><dt>Daily drift recall</dt><dd>{percent(entityBehavior.recall)}</dd></div>
      <div><dt>Daily drift FPR</dt><dd>{percent(entityBehavior.false_positive_rate)}</dd></div>
      <div><dt>Ranked identities</dt><dd>{entityBehavior.ranked_entity_count??'—'}</dd></div>
      <div><dt>Top-10 identity precision</dt><dd>{percent(entityBehavior.top_10_precision)}</dd></div>
      <div><dt>Top-10 identity recall</dt><dd>{percent(entityBehavior.top_10_recall)}</dd></div>
    </dl></section>}

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
