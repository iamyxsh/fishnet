import { useState, useCallback } from "react";
import { Outlet, useLocation } from "react-router-dom";
import { Sidebar } from "./Sidebar";
import { useFetch } from "@/hooks/use-fetch";
import { useAlerts } from "@/hooks/use-alerts";
import { fetchStatus } from "@/api/endpoints/status";
import { ROUTES } from "@/lib/constants";

const routeTitles: Record<string, string> = {
  [ROUTES.HOME]: "Dashboard",
  [ROUTES.SETTINGS]: "Settings",
  [ROUTES.ALERTS]: "Alerts",
};

const routeSubtitles: Record<string, string> = {
  [ROUTES.HOME]: "Overview and control center for your Fishnet instance",
  [ROUTES.SETTINGS]: "User preferences and integrations",
  [ROUTES.ALERTS]: "Monitor and manage security and budget alerts",
};

export function Shell() {
  const [collapsed, setCollapsed] = useState(() => {
    if (typeof window === "undefined") return false;
    return localStorage.getItem("sidebar-collapsed") === "true";
  });

  const location = useLocation();
  const title = routeTitles[location.pathname] ?? "Fishnet";
  const subtitle = routeSubtitles[location.pathname];

  const { data: status } = useFetch(fetchStatus);
  const { undismissed } = useAlerts();

  const handleToggle = useCallback(() => {
    setCollapsed((prev) => {
      const next = !prev;
      localStorage.setItem("sidebar-collapsed", String(next));
      return next;
    });
  }, []);

  return (
    <div className="flex h-screen overflow-hidden bg-bg">
      <Sidebar
        collapsed={collapsed}
        onToggle={handleToggle}
        proxyStatus={status?.proxy}
        version={status?.version}
        alertCount={undismissed.length}
      />
      <div className="flex flex-1 flex-col overflow-hidden">
        {/* Header row */}
        <header className="shrink-0 px-10 pt-10 pb-2">
          <h1 className="text-2xl font-bold tracking-tight text-text">
            {title}
          </h1>
          {subtitle && (
            <p className="mt-1 text-sm text-text-secondary">{subtitle}</p>
          )}
        </header>

        {/* Main content with page enter animation */}
        <main
          key={location.pathname}
          className="page-enter flex-1 overflow-y-auto px-10 py-6"
        >
          <Outlet />
        </main>
      </div>
    </div>
  );
}
