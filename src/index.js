import React from 'react';
import ReactDOM from 'react-dom';
import './index.css'; // Importing global styles
import App from './App'; // Importing the main App component
import reportWebVitals from './reportWebVitals'; // For measuring performance (optional)

ReactDOM.render(
  <React.StrictMode>
    <App /> {/* Rendering the App component */}
  </React.StrictMode>,
  document.getElementById('root') // Attaching the React app to the 'root' div in index.html
);

// If you want to start measuring performance in your app, pass a function
// to log results (for example: reportWebVitals(console.log))
reportWebVitals();