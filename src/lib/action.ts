"use server";

import { redirect } from "next/navigation";
import connectDB from "./db";
import { User } from "./schema";
import { hash } from "bcryptjs";
import { signIn } from "@/auth";

// 로그인
export async function login(formData: FormData) {
  const email = formData.get("email");
  const password = formData.get("password");

  if (!email || !password) {
    console.log("입력값이 부족합니다.");
    //throw new Error('입력값이 부족합니다.');
    return;
  }

  try {
    //auth.js 연동
    console.log("try", email, password);
    await signIn("credentials", {
      redirect: false,
      callbackUrl: "/",
      email,
      password,
    });
  } catch (err) {
    console.log(err);
  }
  redirect("/");
}

// 회원가입
export async function register(formData: FormData) {
  const name = formData.get("name");
  const email = formData.get("email");
  const password = formData.get("password"); //해쉬처리, 저장 후 보안처리 (bcryptjs 라이브러리)

  if (!name || !email || !password) {
    console.log("입력값이 부족합니다.");
    //throw new Error('입력값이 부족합니다.');
  }
  connectDB();

  //회원 존재 여부 조회
  const existingUser = await User.findOne({ email });
  if (!existingUser) {
    console.log("이미 가입된 회원입니다.");
  }

  //없는 회원이면 DB 삽입
  const hashedPassword = await hash(String(password), 10);
  const user = new User({
    name,
    email,
    password: hashedPassword,
  });
  await user.save();
  redirect("/login");
}

export async function githubLogin() {
  await signIn("github", { callbackUrl: "/" });
}
