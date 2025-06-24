// SecureService.jsx
import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';

export default function SecureService() {
  const [data, setData] = useState(null);
  const navigate = useNavigate();

  useEffect(() => {
    const fetchService = async () => {
    try {
      const res = await axios.get('https://oauth2-keycloak.apps.rosa.gowtham-rosa.pygl.p3.openshiftapps.com/api/service1', {
  withCredentials: true,
});
      setData(res);
    } catch (err) {
      console.error(err);
      setData(err.response?.data || 'Error fetching service data');
      // If unauthorized, redirect back to / to trigger login
      if (err.response?.status === 401) navigate('/');
    }
  };
    fetchService();
  }, [navigate]);

  if (!data) return <p>Loading...</p>;
  return <div>Service response: {data}</div>;
}
