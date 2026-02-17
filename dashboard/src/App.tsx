import { lazy, Suspense } from "react";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import { ThemeContext } from "@/hooks/use-theme";
import { useThemeProvider } from "@/hooks/use-theme";
import { Shell } from "@/components/layout/Shell";
import { ROUTES } from "@/lib/constants";
import { Skeleton } from "@/components/ui/Skeleton";

// Route-based code splitting
const DashboardPage = lazy(() => import("@/pages/dashboard/DashboardPage"));
const SettingsPage = lazy(() => import("@/pages/settings/SettingsPage"));

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

  return (
    <ThemeContext value={themeValue}>
      <BrowserRouter>
        <Routes>
          <Route element={<Shell />}>
            <Route
              index
              element={
                <Suspense fallback={<PageLoader />}>
                  <DashboardPage />
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
        </Routes>
      </BrowserRouter>
    </ThemeContext>
  );
}
