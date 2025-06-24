// App.js
import React from 'react';
import { useRoutes } from 'react-router-dom';
import Login from './Login';
import SecureService from './SecureService';

export default function App() {
  const routes = useRoutes([
    { path: '/', element: <Login /> },
    { path: '/secure', element: <SecureService /> },
  ]);
  return routes;
}