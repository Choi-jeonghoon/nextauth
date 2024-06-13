import NextAuth, { CredentialsSignin } from "next-auth";
import Credentials from "next-auth/providers/credentials";
import GitHub from "next-auth/providers/github";
import { User } from "./lib/schema";
import connectDB from "./lib/db";
import { compare } from "bcryptjs";

export const { handlers, signIn, signOut, auth } = NextAuth({
  providers: [
    Credentials({
      name: "Credentials",
      credentials: {
        email: { label: "Email" },
        password: { label: "Password", type: "password" },
      },
      async authorize(credentials) {
        console.log("credentials", credentials);
        const { email, password } = credentials;
        if (!email || !password) {
          throw new CredentialsSignin("입력값이 부족합니다.");
        }

        //DB 연동
        connectDB();
        const user = await User.findOne({ email }).select("+password +role");
        if (!user) {
          throw new CredentialsSignin("가입되지 않은 회원입니다.");
        }
        // 사용자가 입력한 비밀번호와 데이터 베이스의 비밀번호와 일치하는지 확인
        // String은 타입오류 해결
        const isMatched = await compare(String(password), user.password);
        if (!isMatched) {
          throw new CredentialsSignin("비밀번호가 일치하지 않습니다.");
        }
        // 유효한 사용자다!!!
        return {
          name: user.name,
          email: user.email,
          role: user.role,
          id: user._id, // _id 는 몽고 db 자동 생성 아이디
        };

        return null;
      },
    }),
    GitHub({
      clientId: process.env.GITHUB_CLIENT_ID,
      clientSecret: process.env.GITHUB_CLIENT_SECRET,
    }),
  ],
  callbacks: {
    signIn: async ({ user, account }: { user: any; account: any }) => {
      console.log("signIn", user, account);
      if (account?.provider === "github") {
        //로직을 구현할거니까
        const { name, email } = user;
        await connectDB(); // mongodb 연결
        const existingUser = await User.findOne({
          email,
          authProviderId: "github",
        });
        if (!existingUser) {
          //소셜 가입
          await new User({
            name,
            email,
            authProviderId: "github",
            role: "user",
          }).save();
        }
        const socialUser = await User.findOne({ authProviderId: "github" });

        user.role = socialUser?.role || "user";
        user.id = socialUser?._id || null;
        return true;
      } else {
        //크레덴셜 통과
        return true;
      }
      // return false;
    },
    async jwt({ token, user }: { token: any; user: any }) {
      console.log("jwt", token, user);
      if (user) {
        token.role = user.role; // JWT 토큰에 사용자 권한 추가
        token.id = user.id; // JWT 토큰에 사용자 ID 추가
      }
      return token;
    },
    async session({ session, token }: { session: any; token: any }) {
      if (token?.role) {
        session.user.role = token.role;
        session.user.id = token.id;
      }
      return session;
    },
  },
});
