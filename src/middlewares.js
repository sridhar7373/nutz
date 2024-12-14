const jwt = require("jsonwebtoken");
const { PrismaClient } = require("@prisma/client");

const authMiddleware = async (req, res, next) => {
    try
    {
        const token = req.headers.authorization;
        if(!token)
        {
            return res.status(401).json({
                error: "Unauthorized"
            });
        }
        const jwtToken = token.split(" ")[1];
        const decoded = jwt.verify(jwtToken, process.env.JWT_SECRET);
        const userId = decoded.user?.id;
        if(!userId)
        {
            return res.status(401).json({
                error: "Unauthorized"
            });
        }
        
        const prisma = new PrismaClient();
        const existingUser = await prisma.users.findUnique({
            where : {
                id: userId
            }
        });
        if(!existingUser)
        {
            return res.status(401).json({
                error: "Unauthorized"
            });
        }
        req.user = decoded.user;
        next();
    }
    catch (error) {
        console.log(error);
        return res.status(500).json({
            error: "Something went wrong"
        });
    }
}
module.exports = authMiddleware;