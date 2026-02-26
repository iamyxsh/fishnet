import { lazy, Suspense } from "react";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { ThemeContext, useThemeProvider } from "@/hooks/use-theme";
import { AuthContext, useAuthProvider } from "@/hooks/use-auth";
import { Shell } from "@/components/layout/Shell";
import { ProtectedRoute } from "@/components/auth/ProtectedRoute";
import { PublicRoute } from "@/components/auth/PublicRoute";
import { ROUTES } from "@/lib/constants";
import { Skeleton } from "@/components/ui/Skeleton";

// Route-based code splitting
const DashboardPage = lazy(() => import("@/pages/dashboard/DashboardPage"));
const SettingsPage = lazy(() => import("@/pages/settings/SettingsPage"));
const AlertsPage = lazy(() => import("@/pages/alerts/AlertsPage"));
const SpendPage = lazy(() => import("@/pages/spend/SpendPage"));
const OnchainPage = lazy(() => import("@/pages/onchain/OnchainPage"));
const CredentialsPage = lazy(() => import("@/pages/credentials/CredentialsPage"));
const LoginPage = lazy(() => import("@/pages/login/LoginPage"));

function PageLoader() {
  return (
    <div className="space-y-4">
      <Skeleton className="h-8 w-48" />
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
        <Skeleton className="h-32" />
        <Skeleton className="h-32" />
        <Skeleton className="h-32" />
      </div>
    </div>
  );
}

export default function App() {
  const themeValue = useThemeProvider();
  const authValue = useAuthProvider();

  return (
    <AuthContext value={authValue}>
      <ThemeContext value={themeValue}>
        <BrowserRouter>
          <Routes>
            {/* Public: Login page */}
            <Route
              path={ROUTES.LOGIN}
              element={
                <PublicRoute>
                  <Suspense
                    fallback={
                      <div
                        className="h-screen"
                        style={{ background: "#FAFAFA" }}
                      />
                    }
                  >
                    <LoginPage />
                  </Suspense>
                </PublicRoute>
              }
            />

            {/* Protected: Dashboard shell */}
            <Route
              element={
                <ProtectedRoute>
                  <Shell />
                </ProtectedRoute>
              }
            >
              <Route
                index
                element={
                  <Suspense fallback={<PageLoader />}>
                    <DashboardPage />
                  </Suspense>
                }
              />
              <Route
                path={ROUTES.ALERTS}
                element={
                  <Suspense fallback={<PageLoader />}>
                    <AlertsPage />
                  </Suspense>
                }
              />
              <Route
                path={ROUTES.SPEND}
                element={
                  <Suspense fallback={<PageLoader />}>
                    <SpendPage />
                  </Suspense>
                }
              />
              <Route
                path={ROUTES.ONCHAIN}
                element={
                  <Suspense fallback={<PageLoader />}>
                    <OnchainPage />
                  </Suspense>
                }
              />
              <Route
                path={ROUTES.CREDENTIALS}
                element={
                  <Suspense fallback={<PageLoader />}>
                    <CredentialsPage />
                  </Suspense>
                }
              />
              <Route
                path={ROUTES.SETTINGS}
                element={
                  <Suspense fallback={<PageLoader />}>
                    <SettingsPage />
                  </Suspense>
                }
              />
            </Route>

            {/* Catch-all → login */}
            <Route path="*" element={<Navigate to={ROUTES.LOGIN} replace />} />
          </Routes>
        </BrowserRouter>
      </ThemeContext>
    </AuthContext>
  );
}
