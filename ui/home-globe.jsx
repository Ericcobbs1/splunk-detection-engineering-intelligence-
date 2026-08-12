import React, {useState} from 'react';
import {createRoot} from 'react-dom/client';

const APP_STATIC = '/static/app/splunk_detection_engineering_intelligence';
const EARTH_TEXTURE = `${APP_STATIC}/dei_earth_360_v3.png?v=107`;
const EARTH_FALLBACK = `${APP_STATIC}/dei_realistic_earth_v1.webp?v=107`;

function HomeGlobe() {
  const [state, setState] = useState('loading');

  return (
    <div className={`dei-react-earth dei-react-earth--${state}`} aria-hidden="true" data-renderer="react">
      <div className="dei-react-earth-track">
        <img src={EARTH_TEXTURE} alt="" onLoad={() => setState('ready')} onError={() => setState('fallback')} />
        <img src={EARTH_TEXTURE} alt="" />
      </div>
      <img className="dei-react-earth-fallback" src={EARTH_FALLBACK} alt="" />
      <span className="dei-react-earth-shade" />
    </div>
  );
}

function mountHomeGlobe() {
  const host = document.getElementById('dei-earth-react-root');
  if (!host || host.dataset.reactMounted === 'true') return Boolean(host);
  host.dataset.reactMounted = 'true';
  createRoot(host).render(<HomeGlobe />);
  return true;
}

if (!mountHomeGlobe()) {
  document.addEventListener('DOMContentLoaded', mountHomeGlobe, {once: true});
}

window.DEIHomeGlobe = {mount: mountHomeGlobe};
