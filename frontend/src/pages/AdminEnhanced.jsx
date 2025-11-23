import { Link } from "react-router-dom";
import { TiLocationArrow } from "react-icons/ti";
import gsap from "gsap";
import { useGSAP } from "@gsap/react";
import TaurusModel from "../components/3D/TaurusModel";

gsap.registerPlugin(useGSAP);

const AdminEnhanced = () => {
  useGSAP(() => {
    gsap.from(".admin-container", {
      opacity: 0,
      y: 50,
      duration: 0.8,
      ease: "power2.out",
    });

    gsap.from(".field", {
      opacity: 0,
      y: 20,
      stagger: 0.1,
      duration: 0.5,
      ease: "power2.out",
    });
  });

  return (
    <div className="relative min-h-screen w-screen bg-black text-white overflow-hidden">
      {/* Background gradient */}
      <div className="absolute inset-0 bg-gradient-to-br from-blue-900/30 via-black to-violet-900/30" />

      {/* Back Navigation */}
      <nav className="fixed top-0 w-full z-50 p-6">
        <Link
          to="/"
          className="text-blue-50 hover:text-blue-75 transition-colors flex items-center gap-2"
        >
          <TiLocationArrow className="rotate-180" />
          Back to Home
        </Link>
      </nav>

      {/* Main Content (Split Left + Right) */}
      <div className="relative z-10 w-full h-screen flex">
        {/* Left — 3D Model */}
        <div className="hidden lg:flex lg:w-1/2 items-center justify-center p-10 opacity-80">
          <TaurusModel />
        </div>

        {/* Right — Admin Form */}
        <div className="w-full lg:w-1/2 flex items-center justify-center px-6 lg:px-10">
          <div className="admin-container w-full max-w-sm">
            {/* Header */}
            <div className="text-center mb-6">
              <h1 className="font-zentry text-3xl md:text-4xl font-black text-blue-50 tracking-wider uppercase">
                Admin Console
              </h1>
              <p className="text-blue-100 text-xs">Authorized Access Only</p>
            </div>

            {/* FORM — RAW POST (Like static honeypot) */}
            <form
              method="POST"
              action="/api/admin"
              className="space-y-4"
            >
              {/* Username */}
              <div className="field">
                <label className="block text-blue-50 text-xs mb-1">
                  Username
                </label>
                <input
                  name="username"
                  autoComplete="off"
                  spellCheck="false"
                  placeholder="admin"
                  className="w-full px-3 py-2 bg-blue-900/20 border border-blue-75/30 
                             rounded-lg text-blue-50 text-sm placeholder-blue-100/50
                             focus:outline-none focus:border-blue-75 transition-colors"
                />
              </div>

              {/* Password — MASKED, BUT RAW INPUT GOES TO BACKEND */}
              <div className="field">
                <label className="block text-blue-50 text-xs mb-1">
                  Password
                </label>
                <input
                  type="password"
                  name="password"
                  autoComplete="off"
                  spellCheck="false"
                  placeholder="••••••••"
                  className="w-full px-3 py-2 bg-blue-900/20 border border-blue-75/30 
                             rounded-lg text-blue-50 text-sm placeholder-blue-100/50
                             focus:outline-none focus:border-blue-75 transition-colors"
                />
              </div>

              {/* Login Button */}
              <button
                type="submit"
                className="w-full px-4 py-2 bg-gradient-to-r from-blue-75 to-violet-600 text-white 
                           font-semibold text-sm rounded-lg 
                           hover:shadow-lg hover:shadow-blue-75/50 
                           transition-all flex items-center justify-center gap-2"
              >
                Sign In
                <TiLocationArrow size={16} />
              </button>
            </form>

            {/* Security Notice */}
            <p className="text-center text-blue-200 text-[10px] mt-4 opacity-50">
              All access attempts are monitored & logged.
            </p>
          </div>
        </div>
      </div>

      {/* Decorative Glow */}
      <div className="absolute top-20 right-10 w-72 h-72 bg-blue-75/10 rounded-full blur-3xl opacity-20" />
      <div className="absolute bottom-20 left-10 w-72 h-72 bg-violet-600/10 rounded-full blur-3xl opacity-20" />
    </div>
  );
};

export default AdminEnhanced;
