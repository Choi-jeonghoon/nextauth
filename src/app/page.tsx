import { getSession } from "@/lib/getsession";

export default async function Home() {
  const session = await getSession();
  return (
    <>
      <h1>Home Component</h1>
      <h1>{JSON.stringify(session, null, 2)}</h1>
    </>
  );
}
