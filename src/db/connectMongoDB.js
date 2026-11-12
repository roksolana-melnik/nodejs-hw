import mongoose from 'mongoose';

export const connectMongoDB = async () => {
  await mongoose.connect(process.env.MONGO_URL, { family: 4 });
  console.log('✅ MongoDB connection established successfully');
};
