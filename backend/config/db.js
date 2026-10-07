const mongoose = require("mongoose");

const connectDB = async () => {
  const mongoUri =
    process.env.MONGO_URI ||
    process.env.MONGODB_URI;

  if (!mongoUri) {
    throw new Error(
      "MONGO_URI is not defined in backend/.env"
    );
  }

  try {
    const connection =
      await mongoose.connect(mongoUri);

    console.log(
      `MongoDB connected: ${connection.connection.host}`
    );

    return connection;
  } catch (error) {
    console.error(
      "MongoDB connection failed:",
      error.message
    );

    throw error;
  }
};

module.exports = connectDB;