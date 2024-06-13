import { githubLogin, login } from "@/lib/action";

export default function LoginForm() {
  return (
    <>
      <form action={login}>
        <input type="text" name="email" placeholder="Enter Your Email" />
        <input
          type="password"
          name="password"
          placeholder="Enter Your Password"
        />
        <button>로그인</button>
      </form>
      <form action={githubLogin}>
        <button>Github로그인</button>
      </form>
    </>
  );
}
