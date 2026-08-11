import React from 'react';
import { createRoot } from 'react-dom/client';
import Button from '@splunk/react-ui/Button';
import SplunkThemeProvider from '@splunk/themes/SplunkThemeProvider';

function AnalystGuide({step, stepNumber, totalSteps, onBack, onClose, onFocusTarget}) {
  const progress = `${Math.round((stepNumber / totalSteps) * 100)}%`;
  return (
    <section className="dei-next-guide" role="dialog" aria-modal="false" aria-labelledby="dei-guide-title" aria-describedby="dei-guide-instruction">
      <header className="dei-next-guide-header">
        <div>
          <span className="dei-next-guide-kicker">Analyst workflow · {stepNumber}/{totalSteps}</span>
          <h2 id="dei-guide-title">{step.title}</h2>
        </div>
        <button className="dei-next-guide-close" type="button" aria-label="Close guided workflow" onClick={onClose}>×</button>
      </header>
      <p id="dei-guide-instruction" className="dei-next-guide-instruction">{step.instruction}</p>
      {step.details && <ul className="dei-next-guide-details">{step.details.map((detail) => <li key={detail}>{detail}</li>)}</ul>}
      <div className="dei-next-guide-action">
        <span aria-hidden="true">{stepNumber}</span>
        <div><small>{step.completion ? 'Workflow complete' : 'Do this now'}</small><strong>{step.actionLabel}</strong></div>
      </div>
      <div className="dei-next-guide-status" role="status" aria-live="polite">
        <i aria-hidden="true" /> {step.completion ? 'Detection enabled and ready to manage' : 'Waiting for this action to complete'}
      </div>
      <div className="dei-next-guide-progress" role="progressbar" aria-valuemin="1" aria-valuemax={totalSteps} aria-valuenow={stepNumber}>
        <span style={{width: progress}} />
      </div>
      <footer className="dei-next-guide-footer">
        <Button appearance="secondary" disabled={stepNumber === 1} onClick={onBack}>Back</Button>
        <Button appearance="primary" onClick={step.completion ? onClose : onFocusTarget}>{step.completion ? 'Finish' : 'Show me'}</Button>
      </footer>
      <p className="dei-next-guide-hint">{step.completion ? 'You can restart this guide from the Home page at any time.' : 'The guide advances automatically after you complete the highlighted action. Press Esc to exit.'}</p>
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
