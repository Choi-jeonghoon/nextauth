import { getSession } from "@/lib/getsession";
import { redirect } from "next/navigation";

export default async function layout({
  children
}: {
  children: React.ReactNode;
}) {
  const session = await getSession();
  if (session) redirect("/");
  console.log(session);
  return <>{children}</>;
}
