import { register } from "@/lib/action";

export default function RegisterForm() {
  return (
    <>
      <form action={register}>
        <input type="text" name="name" placeholder="Enter Your Name" />
        <input type="email" name="email" placeholder="Enter Your Email" />
        <input
          type="password"
          name="password"
          placeholder="Enter Your Password"
        />
        <button>회원가입</button>
      </form>
    </>
  );
}
