import React from "react";
import "./homestyle.css";
import logo from "./logo.png"; // same folder, simple import

export const Header = () => {
  return (
    <header className="header">
      <div className="logo">
        <img src={logo} alt="Logo" />
      </div>
      <h1 className="site-title">AI Code Debugging Website</h1>
      <nav className="nav">
        <ul className="nav-left">
          <li className="nav-item nav-item-bold">Home</li>
          <li className="nav-item">Debug Code</li>
          <li className="nav-item">About</li>
        </ul>
        <div className="nav-right">
          <span className="login">LOGIN</span>
          <button className="signup">SIGN UP</button>
        </div>
      </nav>
    </header>
  );
};
