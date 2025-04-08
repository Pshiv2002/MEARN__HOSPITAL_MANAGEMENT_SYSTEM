export const generateToken = (user, message, statusCode, res) => {
  const token = user.generateJsonWebToken();

  // Dynamically set token based on role
  const cookieName = user.role === "Admin" ? "adminToken" : "patientToken";

  console.log("Generated Token:", token);
  console.log("Assigned Cookie:", cookieName, "for role:", user.role); // ✅ Debugging

  res
    .status(statusCode)
    .cookie(cookieName, token, {
      expires: new Date(Date.now() + process.env.COOKIE_EXPIRE * 24 * 60 * 60 * 1000),
      httpOnly: true,
      secure: true, // Change to true in production
      sameSite: "None",
    })
    .json({
      success: true,
      message,
      user,
      token,
    });
};
