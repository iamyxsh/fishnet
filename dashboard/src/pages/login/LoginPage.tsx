import { useState, useEffect, useCallback } from "react";
import { useAuth } from "@/hooks/use-auth";
import { FetchError } from "@/api/client";
import { cn } from "@/lib/cn";
import {
  Shield,
  Lock,
  Fingerprint,
  Eye,
  EyeOff,
  ArrowRight,
  Loader2,
} from "lucide-react";

type Mode = "login" | "setup";

export default function LoginPage() {
  const { initialized, login, setup } = useAuth();
  const [mode, setMode] = useState<Mode>("login");

  // Form state
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  // Auto-detect mode from backend state
  useEffect(() => {
    if (!initialized) setMode("setup");
  }, [initialized]);

  // Force light theme on login page
  useEffect(() => {
    document.documentElement.classList.add("light");
    document.documentElement.style.background = "#FAFAFA";

    return () => {
      const stored = localStorage.getItem("theme");
      if (stored !== "light") {
        document.documentElement.classList.remove("light");
        document.documentElement.style.background = "#0A0A0B";
      }
    };
  }, []);

  const handleSubmit = useCallback(
    async (e: React.FormEvent) => {
      e.preventDefault();
      setError(null);

      // Client-side validation
      if (password.length < 8) {
        setError("Password must be at least 8 characters");
        return;
      }
      if (mode === "setup" && password !== confirm) {
        setError("Passwords do not match");
        return;
      }

      setSubmitting(true);
      try {
        if (mode === "setup") {
          await setup(password, confirm);
        } else {
          await login(password);
        }
        // Navigation happens via PublicRoute redirect on auth state change
      } catch (err) {
        if (err instanceof FetchError) {
          const body = err.body as { error: string; retry_after_seconds?: number };
          if (err.status === 429 && body.retry_after_seconds) {
            setError(`Too many attempts. Try again in ${body.retry_after_seconds}s`);
          } else {
            setError(body.error);
          }
        } else {
          setError("An unexpected error occurred");
        }
      } finally {
        setSubmitting(false);
      }
    },
    [password, confirm, mode, login, setup],
  );

  const toggleMode = useCallback(() => {
    setMode((m) => (m === "login" ? "setup" : "login"));
    setError(null);
    setPassword("");
    setConfirm("");
  }, []);

  return (
    <div className="flex h-screen">
      {/* ── Left Panel: Brand Hero ──────────────────────── */}
      <BrandPanel />

      {/* ── Right Panel: Form ───────────────────────────── */}
      <div className="relative flex w-full flex-col items-center justify-center overflow-y-auto bg-[#FAFAFA] px-6 lg:w-[48%]">
        {/* Mobile logo (hidden on desktop) */}
        <div className="mb-8 flex items-center gap-2.5 lg:hidden">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-[#E63946]">
            <Shield size={18} className="text-white" />
          </div>
          <span className="text-lg font-bold tracking-tight text-[#18181B]">
            Fishnet
          </span>
        </div>

        <div className="w-full max-w-[400px]">
          {/* Header */}
          <h1 className="text-[26px] font-bold tracking-tight text-[#18181B]">
            {mode === "login" ? "Welcome back" : "Create your password"}
          </h1>
          <p className="mt-2 text-sm text-[#71717A]">
            {mode === "login"
              ? "Sign in to access your Fishnet dashboard."
              : "Set up Fishnet to protect your agent's credentials."}
          </p>

          {/* Form */}
          <form onSubmit={handleSubmit} className="mt-8 space-y-4">
            {/* Password field */}
            <div>
              <label className="mb-1.5 block text-[13px] font-medium text-[#18181B]">
                Password
              </label>
              <div className="relative">
                <input
                  type={showPassword ? "text" : "password"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Enter your password"
                  autoComplete={mode === "setup" ? "new-password" : "current-password"}
                  className={cn(
                    "h-10 w-full rounded-lg border bg-white px-3.5 pr-10 text-sm text-[#18181B] outline-none transition-all duration-150",
                    "placeholder:text-[#A1A1AA]",
                    "focus:border-[#E63946] focus:ring-2 focus:ring-[#E63946]/10",
                    error
                      ? "border-[#EF4444]"
                      : "border-[#E4E4E7]",
                  )}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword((v) => !v)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-[#A1A1AA] transition-colors duration-100 hover:text-[#52525B]"
                  tabIndex={-1}
                >
                  {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
            </div>

            {/* Confirm password (setup mode only) */}
            {mode === "setup" && (
              <div>
                <label className="mb-1.5 block text-[13px] font-medium text-[#18181B]">
                  Confirm Password
                </label>
                <div className="relative">
                  <input
                    type={showConfirm ? "text" : "password"}
                    value={confirm}
                    onChange={(e) => setConfirm(e.target.value)}
                    placeholder="Confirm your password"
                    autoComplete="new-password"
                    className={cn(
                      "h-10 w-full rounded-lg border bg-white px-3.5 pr-10 text-sm text-[#18181B] outline-none transition-all duration-150",
                      "placeholder:text-[#A1A1AA]",
                      "focus:border-[#E63946] focus:ring-2 focus:ring-[#E63946]/10",
                      error && mode === "setup"
                        ? "border-[#EF4444]"
                        : "border-[#E4E4E7]",
                    )}
                  />
                  <button
                    type="button"
                    onClick={() => setShowConfirm((v) => !v)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-[#A1A1AA] transition-colors duration-100 hover:text-[#52525B]"
                    tabIndex={-1}
                  >
                    {showConfirm ? <EyeOff size={16} /> : <Eye size={16} />}
                  </button>
                </div>
              </div>
            )}

            {/* Error message */}
            {error && (
              <p className="text-sm font-medium text-[#EF4444]">{error}</p>
            )}

            {/* Submit button */}
            <button
              type="submit"
              disabled={submitting}
              className={cn(
                "flex h-10 w-full items-center justify-center gap-2 rounded-lg text-sm font-semibold text-white transition-all duration-150",
                "shadow-[0_1px_2px_rgba(0,0,0,0.05)]",
                submitting
                  ? "cursor-not-allowed bg-[#E63946]/70"
                  : "bg-[#E63946] hover:bg-[#CC2D3B] active:scale-[0.99]",
              )}
            >
              {submitting ? (
                <Loader2 size={16} className="animate-spin" />
              ) : (
                <>
                  {mode === "login" ? "Sign In" : "Create Account"}
                  <ArrowRight size={16} />
                </>
              )}
            </button>
          </form>

          {/* Divider */}
          <div className="my-6 flex items-center gap-3">
            <div className="h-px flex-1 bg-[#E4E4E7]" />
            <span className="text-xs text-[#A1A1AA]">or</span>
            <div className="h-px flex-1 bg-[#E4E4E7]" />
          </div>

          {/* CLI hint */}
          <div className="rounded-lg border border-[#E4E4E7] bg-[#F5F5F5] p-4">
            <p className="mb-2 text-xs font-medium text-[#52525B]">
              Set up via CLI instead
            </p>
            <div className="rounded-md border border-[#E4E4E7] bg-white px-3 py-2">
              <code className="font-mono text-[13px] text-[#18181B]">
                <span className="text-[#A1A1AA]">$ </span>
                fishnet init
              </code>
            </div>
          </div>

          {/* Toggle mode link */}
          <p className="mt-6 text-center text-sm text-[#71717A]">
            {mode === "login" ? (
              <>
                First time?{" "}
                <button
                  type="button"
                  onClick={toggleMode}
                  className="font-medium text-[#E63946] transition-colors duration-100 hover:text-[#CC2D3B]"
                >
                  Set up password
                </button>
              </>
            ) : (
              <>
                Already have a password?{" "}
                <button
                  type="button"
                  onClick={toggleMode}
                  className="font-medium text-[#E63946] transition-colors duration-100 hover:text-[#CC2D3B]"
                >
                  Sign in
                </button>
              </>
            )}
          </p>
        </div>
      </div>
    </div>
  );
}

/* ═══════════════════════════════════════════════════
   Brand Panel — left side (52%), hidden on mobile
   ═══════════════════════════════════════════════════ */

function BrandPanel() {
  return (
    <div
      className="relative hidden w-[52%] flex-col justify-between overflow-hidden p-12 lg:flex"
      style={{ background: "#08080A" }}
    >
      {/* ── Layered background effects ────────────── */}

      {/* Grid overlay */}
      <div
        className="pointer-events-none absolute inset-0"
        style={{
          backgroundImage: `
            linear-gradient(rgba(230,57,70,0.03) 1px, transparent 1px),
            linear-gradient(90deg, rgba(230,57,70,0.03) 1px, transparent 1px)
          `,
          backgroundSize: "48px 48px",
        }}
      />

      {/* Diagonal accent lines */}
      <div
        className="pointer-events-none absolute inset-0"
        style={{
          backgroundImage:
            "repeating-linear-gradient(-45deg, rgba(230,57,70,0.015) 0, rgba(230,57,70,0.015) 1px, transparent 1px, transparent 80px)",
        }}
      />

      {/* Radial glow */}
      <div
        className="pointer-events-none absolute inset-0"
        style={{
          background:
            "radial-gradient(circle 600px at 50% 50%, rgba(230,57,70,0.06), transparent)",
        }}
      />

      {/* Animated scan line */}
      <div className="pointer-events-none absolute inset-0 overflow-hidden">
        <div
          className="login-scan-line absolute left-0 h-px w-full"
          style={{ background: "rgba(230,57,70,0.20)" }}
        />
      </div>

      {/* ── Content ───────────────────────────────── */}

      {/* Top: Logo */}
      <div className="relative z-10 flex items-center gap-3">
        <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-[#E63946]">
          <Shield size={20} className="text-white" />
        </div>
        <span className="text-xl font-bold text-white">Fishnet</span>
      </div>

      {/* Center: Headline + subtext + pills */}
      <div className="relative z-10 max-w-[480px]">
        <h2
          className="text-[42px] font-bold leading-[1.1] tracking-[-0.03em] text-[#F5F5F7]"
        >
          The only door
          <br />
          between your agent
          <br />
          <span className="text-[#E63946]">and the world.</span>
        </h2>

        <p className="mt-6 max-w-[420px] text-[15px] leading-relaxed text-[#71717A]">
          Local-first cryptographic security proxy. Your credentials never leave
          your machine. Every request evaluated, every action audited.
        </p>

        {/* Feature pills */}
        <div className="mt-6 flex flex-wrap gap-2">
          <FeaturePill icon={<Lock size={14} />} label="Encrypted Vault" />
          <FeaturePill icon={<Shield size={14} />} label="Policy Engine" />
          <FeaturePill icon={<Fingerprint size={14} />} label="Permit Signing" />
        </div>
      </div>

      {/* Bottom: Status line */}
      <div className="relative z-10 flex items-center gap-2">
        <span className="h-1.5 w-1.5 rounded-full bg-[#22C55E] status-pulse" />
        <span className="font-mono text-xs text-[#52525B]">
          localhost:8473 &middot; nothing leaves your machine
        </span>
      </div>
    </div>
  );
}

/* ── Feature Pill ───────────────────────────────── */

function FeaturePill({
  icon,
  label,
}: {
  icon: React.ReactNode;
  label: string;
}) {
  return (
    <span className="inline-flex items-center gap-1.5 rounded-full border border-[#1F1F23] bg-[#111113]/60 px-3 py-1.5 backdrop-blur-sm">
      <span className="text-[#E63946]">{icon}</span>
      <span className="text-xs text-[#A1A1AA]">{label}</span>
    </span>
  );
}
