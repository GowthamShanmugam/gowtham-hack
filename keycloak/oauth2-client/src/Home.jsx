function Home() {
  const startLogin = () => {
    window.location.href =
    'https://oauth2-keycloak.apps.rosa.gowtham-rosa.pygl.p3.openshiftapps.com/oauth2/start?rd=' +
        encodeURIComponent('/api/service1');
  };

  return (
    <div>
      <h1>Welcome</h1>
      <button onClick={startLogin}>Login</button>
    </div>
  );
}

export default Home;
