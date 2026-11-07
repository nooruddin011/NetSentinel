import React, { useCallback, useEffect, useState } from 'react'
import { Bar as RBar, BarChart, CartesianGrid, Legend, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { RefreshCw } from 'lucide-react'
import { api } from '../api'
import { useChart } from '../theme'
import { useToast } from '../feedback'
import { Bar, Card, Empty, ErrorNote, PageHead, PALETTE, Spinner, Tabs, canAct, pct } from './ui'

function Confusion({ matrix, classes }) {
  const max = Math.max(1, ...matrix.flat())
  const short = (c) => c.split(' ').map((w) => w[0]).join('').slice(0, 3)
  return (
    <div>
      <div className="cm" style={{ gridTemplateColumns: `40px repeat(${classes.length}, 1fr)` }} role="img" aria-label="Confusion matrix of the ensemble on the hold-out set">
        <span />{classes.map((c) => <span key={c} className="muted" style={{ textAlign: 'center' }} title={c}>{short(c)}</span>)}
        {matrix.map((row, i) => (
          <React.Fragment key={i}>
            <span className="muted" title={classes[i]}>{short(classes[i])}</span>
            {row.map((v, j) => {
              const diag = i === j
              const a = v ? 0.15 + 0.85 * Math.min(1, v / (diag ? max : max / 6)) : 0
              return <span key={j} className="c" title={`true ${classes[i]} → predicted ${classes[j]}: ${v}`} style={v ? { background: diag ? `rgba(var(--ok-rgb),${a})` : `rgba(var(--heat-rgb),${a})` } : undefined}>{v || ''}</span>
            })}
          </React.Fragment>))}
      </div>
      <div className="muted" style={{ fontSize: '.72rem', marginTop: '.4rem' }}>Rows = true class, columns = predicted. Green = correct, red = confusion.</div>
    </div>
  )
}

export default function Models({ user, train, setTrain }) {
  const c = useChart()
  const toast = useToast()
  const [rep, setRep] = useState(null)
  const [error, setError] = useState('')
  const [tab, setTab] = useState('compare')

  const load = useCallback(async () => { try { setRep(await api.model()); setError('') } catch (e) { setError(e.message) } }, [])
  useEffect(() => { load() }, [load])
  // reload the report when a training run that was in progress finishes (even if we were on another page meanwhile)
  const finishedAt = train?.finished_at
  useEffect(() => { if (train?.state === 'done' && finishedAt) { load(); toast('Model training finished. New metrics are shown below.') } }, [finishedAt]) // eslint-disable-line react-hooks/exhaustive-deps

  const retrain = async (quick) => {
    try { setTrain(await api.retrain(quick)) }
    catch (e) { setError(e.message); try { setTrain(await api.retrainStatus()) } catch { /* ignore */ } }
  }
  const showBanner = train && (train.state === 'running' || train.state === 'error' || (train.state === 'done' && train.finished_at && Date.now() / 1000 - train.finished_at < 900))

  if (!rep) return <><ErrorNote error={error} /><Spinner /></>
  const names = Object.keys(rep.models || {})
  const label = (n) => rep.model_info?.[n]?.display || n
  const rocRows = (rep.roc?.ensemble?.fpr || []).map((x, i) => {
    const row = { fpr: x }
    Object.keys(rep.roc).forEach((n) => { row[n] = rep.roc[n].tpr[i] })
    return row
  })
  const cmp = names.map((n) => ({ name: label(n), Accuracy: rep.models[n].accuracy, 'F1 (macro)': rep.models[n].f1, 'ROC-AUC': rep.models[n].roc_auc }))
  const classes = rep.classes || []
  const ens = rep.models.ensemble
  const h = rep.hybrid
  const an = rep.anomaly

  return (
    <>
      <PageHead eyebrow="Analyse" title="Model performance" subtitle={`Trained ${rep.created_at?.slice(0, 10)} on ${rep.dataset?.rows?.toLocaleString()} rows · ${rep.config?.cv_folds}-fold stratified cross-validation · SMOTE on training folds only`}>
        {canAct(user, 'admin') && (
          <div className="row">
            <button className="btn ghost sm" disabled={train?.state === 'running'} onClick={() => retrain(true)}><RefreshCw size={14} /> Quick retrain</button>
            <button className="btn ghost sm" disabled={train?.state === 'running'} onClick={() => retrain(false)}>Full retrain</button>
          </div>)}
      </PageHead>
      <ErrorNote error={error} />
      {rep.dataset?.synthetic && <div className="note warn"><strong>Simulated data.</strong> These models were trained and tested on generated traffic (NSL-KDD/CICIDS-style features). The numbers show that the pipeline works end to end; they are <em>not</em> a benchmark of real-world detection accuracy. See docs/datasets for training on a real capture.</div>}
      {showBanner && (
        <div className={`note ${train.state === 'error' ? 'error' : train.state === 'done' ? 'ok' : 'info'}`}>
          <strong>{train.state === 'running' ? 'Training in progress' : train.state === 'done' ? 'Training complete' : 'Training failed'}</strong> {train.stage && train.state === 'running' && `— ${train.stage}`} {train.state === 'running' && <><Bar value={train.progress} /><div className="muted" style={{ fontSize: '.78rem', marginTop: '.3rem' }}>{Math.round((train.progress || 0) * 100)}% · you can leave this page; progress is kept.</div></>} {train.error}
        </div>)}

      <div className="stats">
        {[['Accuracy', pct(ens.accuracy)], ['Precision (macro)', pct(ens.precision)], ['Recall (macro)', pct(ens.recall)], ['F1 (macro)', pct(ens.f1)], ['ROC-AUC', ens.roc_auc], ['False-positive rate', pct(ens.false_positive_rate, 2)]].map(([k, v]) => (
          <div className="stat" key={k}><div className="stat-top"><span>{k.replace(/\s*\(.*\)/, '')}</span></div><div className="stat-value">{v}</div><div className="stat-sub">weighted ensemble</div></div>))}
      </div>

      <Tabs value={tab} onChange={setTab} tabs={[{ id: 'compare', label: 'Compare models' }, { id: 'roc', label: 'ROC & confusion' }, { id: 'class', label: 'Per attack type' }, { id: 'zero', label: 'Zero-day & hybrid' }]} />

      {tab === 'compare' && (
        <div className="grid">
          <Card title="Hold-out metrics">
            <div className="table-wrap"><table><thead><tr><th>Model</th><th>Approach</th><th>Acc.</th><th>Prec.</th><th>Recall</th><th>F1</th><th>ROC-AUC</th><th>FPR</th><th>CV F1 ± sd</th><th>ms / event</th><th>Weight</th></tr></thead><tbody>
              {names.map((n) => { const m = rep.models[n]; return (
                <tr key={n} title={rep.model_info?.[n]?.complexity}><td><strong>{label(n)}</strong></td><td className="muted">{rep.model_info?.[n]?.approach}</td>
                  <td>{pct(m.accuracy)}</td><td>{pct(m.precision)}</td><td>{pct(m.recall)}</td><td>{pct(m.f1)}</td><td>{m.roc_auc}</td><td>{pct(m.false_positive_rate, 2)}</td>
                  <td>{m.cv_f1_mean !== undefined ? `${m.cv_f1_mean}${m.cv_f1_std !== undefined ? ` ± ${m.cv_f1_std}` : ''}` : '–'}</td><td>{m.infer_ms}</td><td>{m.weight !== undefined ? pct(m.weight, 0) : '–'}</td></tr>) })}
            </tbody></table></div>
            <div className="muted" style={{ fontSize: '.75rem', marginTop: '.5rem' }}>Decision threshold tuned on out-of-fold predictions so that ≈{pct(rep.decision?.target_fpr, 0)} of benign traffic is flagged (τ = {rep.decision?.tau}). Hover a row for time complexity. Available members: {rep.environment?.xgboost ? 'XGBoost ✔' : 'XGBoost ✘ (not installed)'} · {rep.environment?.lightgbm ? 'LightGBM ✔' : 'LightGBM ✘ (not installed)'}.</div>
          </Card>
          <Card title="Model comparison">
            <div className="chart"><ResponsiveContainer><BarChart data={cmp}>
              <CartesianGrid stroke={c.grid} vertical={false} /><XAxis dataKey="name" stroke={c.text} fontSize={11} /><YAxis domain={[0.8, 1]} stroke={c.axis} fontSize={11} width={40} />
              <Tooltip {...c.tip} /><Legend />
              <RBar dataKey="Accuracy" fill={c.ice} radius={[4, 4, 0, 0]} /><RBar dataKey="F1 (macro)" fill={c.accent} radius={[4, 4, 0, 0]} /><RBar dataKey="ROC-AUC" fill={c.ok} radius={[4, 4, 0, 0]} />
            </BarChart></ResponsiveContainer></div>
          </Card>
          {rep.feature_importance?.length > 0 && (
            <Card title="Global feature importance (Random Forest)">
              {rep.feature_importance.slice(0, 10).map((f) => <div key={f.feature} style={{ marginBottom: '.35rem' }}><div className="row" style={{ justifyContent: 'space-between', fontSize: '.82rem' }}><span className="mono">{f.feature}</span><span>{(f.importance * 100).toFixed(1)}%</span></div><Bar value={f.importance * 6} /></div>)}
            </Card>)}
        </div>)}

      {tab === 'roc' && (
        <div className="grid g2">
          <Card title="ROC curve — attack vs. benign">
            <div className="chart" style={{ height: 320 }}><ResponsiveContainer><LineChart data={rocRows}>
              <CartesianGrid stroke={c.grid} /><XAxis dataKey="fpr" type="number" domain={[0, 1]} stroke={c.axis} fontSize={11} label={{ value: 'False-positive rate', position: 'insideBottom', offset: -2, fill: c.text, fontSize: 11 }} />
              <YAxis domain={[0, 1]} stroke={c.axis} fontSize={11} width={36} /><Tooltip {...c.tip} /><Legend />
              {Object.keys(rep.roc).map((n, i) => <Line key={n} dataKey={n} name={`${label(n)} (AUC ${rep.roc[n].auc})`} stroke={PALETTE[i]} strokeWidth={n === 'ensemble' ? 3 : 1.5} dot={false} isAnimationActive={false} />)}
            </LineChart></ResponsiveContainer></div>
          </Card>
          <Card title="Confusion matrix — ensemble"><Confusion matrix={rep.confusion_matrix} classes={classes} /></Card>
        </div>)}

      {tab === 'class' && (
        <Card title="Ensemble — precision / recall / F1 per attack type">
          <div className="table-wrap" style={{ maxHeight: 'none' }}><table><thead><tr><th>Class</th><th>Precision</th><th>Recall</th><th>F1</th><th /><th>Support</th></tr></thead><tbody>
            {Object.entries(ens.per_class).map(([c, m]) => <tr key={c}><td><strong>{c}</strong></td><td>{pct(m.precision)}</td><td>{pct(m.recall)}</td><td>{pct(m.f1)}</td><td style={{ width: '25%' }}><Bar value={m.f1} color={m.f1 >= 0.95 ? 'var(--ok)' : m.f1 >= 0.9 ? 'var(--sev-medium)' : 'var(--danger)'} /></td><td>{m.support}</td></tr>)}
          </tbody></table></div>
        </Card>)}

      {tab === 'zero' && (
        <div className="grid g2">
          <Card title="Anomaly detection (autoencoder)">
            <dl className="kv">
              <dt>Benign flagged</dt><dd>{pct(an?.benign_flag_rate, 2)}</dd><dt>Known attacks flagged</dt><dd>{pct(an?.known_attack_flag_rate)}</dd>
              <dt>Novel family flagged</dt><dd>{pct(an?.novel_flag_rate)}</dd><dt>ROC-AUC vs benign</dt><dd>Autoencoder {an?.autoencoder_auc_vs_benign} · Isolation Forest {an?.isolation_forest_auc_vs_benign}</dd>
            </dl>
            <div className="note" style={{ marginTop: '.7rem' }}>The autoencoder separates anomalous from normal traffic very well, but it <strong>cannot tell a novel attack from a known one</strong> (attacks are anomalous by nature). The “Zero-Day” label therefore comes from the classifier being unsure, which trades off against naming known attacks correctly.</div>
          </Card>
          <Card title="Full hybrid pipeline (signature + ensemble + anomaly)">
            {h ? <>
              <dl className="kv">
                <dt>Benign false positives</dt><dd>{pct(h.benign_false_positive_rate, 2)}</dd><dt>Known attacks detected</dt><dd>{pct(h.known_attack_detection_rate)}</dd>
                <dt>Known attacks, correct type</dt><dd>{pct(h.known_attack_type_accuracy)}</dd><dt>Novel traffic detected</dt><dd>{pct(h.zero_day_detected_as_threat)} of {h.zero_day_samples}</dd>
                <dt>…labelled Zero-Day</dt><dd>{pct(h.zero_day_labelled_zero_day)} (threshold {h.unknown_conf})</dd>
              </dl>
              {h.unknown_conf_sweep && <div className="table-wrap" style={{ marginTop: '.7rem' }}><table><thead><tr><th>Zero-Day threshold</th><th>Known: correct type</th><th>Known → “Zero-Day”</th><th>Novel → “Zero-Day”</th></tr></thead><tbody>
                {h.unknown_conf_sweep.map((s) => <tr key={s.unknown_conf} style={s.unknown_conf === h.unknown_conf ? { background: 'color-mix(in srgb, var(--accent) 14%, transparent)' } : undefined}><td>{s.unknown_conf}</td><td>{pct(s.known_type_accuracy)}</td><td>{pct(s.known_labelled_zero_day)}</td><td>{pct(s.novel_labelled_zero_day)}</td></tr>)}
              </tbody></table></div>}
            </> : <Empty>No novel-family evaluation in this run.</Empty>}
          </Card>
        </div>)}
    </>
  )
}
