import mongoose from "mongoose";

const connectDB = async () => {
  try {
    if (mongoose.connection.readyState >= 1) {
      console.log("Already connected to MongoDB");
      return;
    }
    await mongoose.connect(process.env.MONGO_URI as string);
    console.log(`MongoDB connected`);
  } catch (err) {
    console.log(`Error: ${err}`);
    process.exit(1);
  }
};

export default connectDB;
