import { Navigate } from "react-router-dom";
import { useAuth } from "@/hooks/use-auth";
import { ROUTES } from "@/lib/constants";

export function PublicRoute({ children }: { children: React.ReactNode }) {
  const { authenticated, loading } = useAuth();

  if (loading) {
    return (
      <div
        className="flex h-screen items-center justify-center"
        style={{ background: "#FAFAFA" }}
      >
        <div className="h-8 w-8 animate-spin rounded-full border-2 border-[#E63946] border-t-transparent" />
      </div>
    );
  }

  if (authenticated) {
    return <Navigate to={ROUTES.HOME} replace />;
  }

  return <>{children}</>;
}
