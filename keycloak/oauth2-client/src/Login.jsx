// Login.jsx
import React from 'react';

export default function Login() {
  const login = () => {
    const redirect = encodeURIComponent(
      'https://oauth2-client.apps.rosa.gowtham-rosa.pygl.p3.openshiftapps.com/secure'
    );
    window.location.href =
      `https://oauth2-keycloak.apps.rosa.gowtham-rosa.pygl.p3.openshiftapps.com/oauth2/start?rd=${redirect}`;
  };

  return (
    <div>
      <button onClick={login}>Login & Go to Service</button>
    </div>
  );
}
