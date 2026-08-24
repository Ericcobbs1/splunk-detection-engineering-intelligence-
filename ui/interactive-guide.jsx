import React, {useState} from 'react';
import { createRoot } from 'react-dom/client';
import Button from '@splunk/react-ui/Button';
import SplunkThemeProvider from '@splunk/themes/SplunkThemeProvider';

function AnalystGuide({step, stepNumber, totalSteps, reviewMode, onBack, onForward, onClose, onFocusTarget, onContinueOperations, onFinishCore}) {
  const [collapsed, setCollapsed] = useState(false);
  const progress = `${Math.round((stepNumber / totalSteps) * 100)}%`;
  return (
    <section className={`dei-next-guide${collapsed ? ' is-collapsed' : ''}`} role="dialog" aria-modal="false" aria-labelledby="dei-guide-title" aria-describedby="dei-guide-instruction">
      <header className="dei-next-guide-header">
        <div>
          <span className="dei-next-guide-kicker">{step.phase || 'Build and deploy'} · {stepNumber}/{totalSteps}</span>
          <h2 id="dei-guide-title">{step.title}</h2>
        </div>
        <div className="dei-next-guide-window-actions"><button className="dei-next-guide-collapse" type="button" aria-label={collapsed ? 'Expand guided workflow' : 'Collapse guided workflow'} onClick={() => setCollapsed(!collapsed)}>{collapsed ? '□' : '—'}</button><button className="dei-next-guide-close" type="button" aria-label="Close guided workflow" onClick={onClose}>×</button></div>
      </header>
      <p id="dei-guide-instruction" className="dei-next-guide-instruction">{step.instruction}</p>
      {step.details && <ul className="dei-next-guide-details">{step.details.map((detail) => <li key={detail}>{detail}</li>)}</ul>}
      <div className="dei-next-guide-action">
        <span aria-hidden="true">{stepNumber}</span>
        <div><small>{step.completion ? 'Workflow complete' : (step.operationsChoice ? 'Choose the next module' : 'Do this now')}</small><strong>{step.actionLabel || step.actionText}</strong></div>
      </div>
      <div className="dei-next-guide-status" role="status" aria-live="polite">
        <i aria-hidden="true" /> <span>{step.completion ? 'Detection lifecycle walkthrough complete' : (step.operationsChoice ? 'Core build and deployment workflow complete' : 'Waiting for this action to complete')}</span>
      </div>
      <div className="dei-next-guide-progress" role="progressbar" aria-valuemin="1" aria-valuemax={totalSteps} aria-valuenow={stepNumber}>
        <span style={{width: progress}} />
      </div>
      <footer className="dei-next-guide-footer">
        <Button appearance="secondary" disabled={stepNumber === 1} onClick={onBack}>Back</Button>
        {step.operationsChoice ? <Button appearance="secondary" onClick={onFinishCore}>Finish core tutorial</Button> : null}
        <Button appearance="primary" onClick={reviewMode ? onForward : (step.operationsChoice ? onContinueOperations : (step.completion ? onClose : onFocusTarget))}>{reviewMode ? 'Next' : (step.operationsChoice ? 'Continue: operate & tune' : (step.completion ? 'Finish' : 'Show me'))}</Button>
      </footer>
      <p className="dei-next-guide-hint">{reviewMode ? 'Review mode does not repeat or change completed lifecycle actions. Select Next to return to the current checkpoint.' : (step.operationsChoice ? 'Operational tuning is optional and should be driven by real evidence.' : (step.completion ? 'You can restart this guide from the Home page at any time.' : 'The guide advances automatically after you complete the highlighted action. Press Esc to exit.'))}</p>
    </section>
  );
}

let guideRoot = null;

function renderGuide(config) {
  const host = document.getElementById('dei-onboarding-react-root');
  if (!host) return false;
  if (!guideRoot) guideRoot = createRoot(host);
  guideRoot.render(
    <SplunkThemeProvider family="prisma" density="compact" colorScheme="dark">
      <AnalystGuide {...config} />
    </SplunkThemeProvider>
  );
  return true;
}

function unmountGuide() {
  if (guideRoot) guideRoot.unmount();
  guideRoot = null;
}

window.DEIInteractiveGuide = {render: renderGuide, unmount: unmountGuide};
