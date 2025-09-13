import JWT from "jsonwebtoken";
import userModel from "../models/usermodel.js";
export const requireSignIn = async (req, res, next) => {
    try {
        const token = req.headers.authorization?.split(" ")[1]; // Bearer <token>
        if (!token) {
            return res.status(401).send({
                success: false,
                message: "No token provided. Please login again.",
            });
        }

        const decode = JWT.verify(token, process.env.JWT_SECRET);
        req.user = decode;
        next();
    } catch (err) {
        console.log("JWT Verification Error:", err);
        return res.status(401).send({
            success: false,
            message: "Unauthorized access. Please login again.",
        });
    }
};

//admin middleware
export const isAdmin = async (req, res, next) => {
    try {
        const user = await userModel.findById(req.user._id);
        if (!user || user.role !== 1) {
            return res.status(403).send({
                success: false,
                message: "Access denied. Admin only.",
            });
        }
        next();
    } catch (err) {
        console.log("Admin Middleware Error:", err);
        return res.status(500).send({
            success: false,
            message: "Server error in admin middleware.",
        });
    }
};

