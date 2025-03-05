import React from "react";
import { BrowserRouter as Router, Route, Routes } from "react-router-dom";
import Home from "./pages/Home";
import Chat from "./pages/Chat";
import Login from "./pages/Login";
import { AuthProvider } from "./context/AuthContext";
import { EncryptionProvider } from "./context/EncryptionContext";

function App() {
  return (
    <AuthProvider>
      <EncryptionProvider>
        <Router>
          <Routes>
            <Route path="/" element={<Home />} />
            <Route path="/chat" element={<Chat />} />
            <Route path="/login" element={<Login />} />
          </Routes>
        </Router>
      </EncryptionProvider>
    </AuthProvider>
  );
}

export default App;