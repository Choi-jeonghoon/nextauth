import { getSession } from "@/lib/getsession";
import { redirect } from "next/navigation";

export default async function layout({
  children
}: {
  children: React.ReactNode;
}) {
  const session: any = await getSession();
  if (!session) redirect("/login");
  if (session.user?.role !== "admin") redirect("/");
  return <>{children}</>;
}
