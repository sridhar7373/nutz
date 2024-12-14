const express = require("express");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const { PrismaClient } = require("@prisma/client");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
const { v4: uuidv4 } = require('uuid');
const authMiddleware = require("./middlewares");


dotenv.config();
const app = express();
app.use(bodyParser.json());

//open routes
app.get("/", (req, res) => {
    res.send("Hello World!");
});

app.post("/api/login", async (req, res) => {
    try
    {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({
                error: "Please fill all the fields"
            });
        }
        const prisma = new PrismaClient();
        const existingUser = await prisma.users.findFirst({
            where: {
                email
            }
        });
        if (!existingUser) {
            return res.status(400).json({
                error: "User does not exist"
            });
        }
        const isMatch = await bcrypt.compare(password, existingUser.password);
        if(!isMatch)
        {
            return res.status(400).json({
                error: "Invalid credentials"
            });
        }
        const payload = {
            user: {
                id: existingUser.id
            }
        };
        const token = await jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: "1d" });
        return res.status(201).json({
            message: "Login successful",
            token
        });
    }
    catch (error) {
        console.log(error);
        return res.status(500).json({
            error: "Something went wrong"
        });
    }
});

app.post("/api/register", async (req, res) => {
    try {
        const { username, email, password } = req.body;
        if (!username || !email || !password) {
            return res.status(400).json({
                error: "Please fill all the fields"
            });
        }
        const prisma = new PrismaClient();
        const existingUser = await prisma.users.findFirst({
            where: {
                email
            }
        });
        if (existingUser) {
            return res.status(400).json({
                error: "User already exists"
            });
        }
        const hasedPassword = await bcrypt.hash(password, 10);
        const user = await prisma.users.create({
            data: {
                username,
                email,
                password: hasedPassword
            }
        });
        if (user) {
            return res.status(200).json({
                message: "User registered successfully"
            });
        }
        else {
            return res.status(500).json({
                error: "Something went wrong"
            });
        }

    }
    catch (error) {
        console.log(error);
        return res.status(500).json({
            error: "Something went wrong"
        });
    }
});

app.post("/api/forgot-password", async (req, res) => {
    try
    {
        const { email } = req.body;
        if (!email) {
            return res.status(400).json({
                error: "Please fill all the fields"
            });
        }
        const prisma = new PrismaClient();
        const existingUser = await prisma.users.findFirst({
            where: {
                email
            }
        });
        if (!existingUser) {
            return res.status(400).json({
                error: "User does not exist"
            });
        }
        const resetToken = uuidv4();
        const payload = {
            user: {
                id: existingUser.id,
                token: resetToken
            }
        };
        await prisma.users.update({
            where:{
                id: existingUser.id
            },
            data: {
                resetPasswordToken: resetToken,
            }
        })
        const jwtToken = await jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: "1h" });
        return res.status(200).json({
            message: "Reset password link sent to your email",
            url: `http://localhost:3000/api/reset-password?token=${jwtToken}`
        });
    }
    catch (error) {
        console.log(error);
        return res.status(500).json({
            error: "Something went wrong"
        });
    }
});

app.post("/api/reset-password", async (req, res) => {
    try
    {
        const { token } = req.query;
        if(!token)
        {
            return res.status(400).json({
                error: "Invalid token"
            });
        }
        const { new_password } = req.body;
        const decoded = await jwt.verify(token, process.env.JWT_SECRET);
        const { id : userId, token: resetToken } = decoded.user;
        if(!userId || !resetToken)
        {
            return res.status(400).json({
                error: "Invalid token"
            });
        }
        const prisma = new PrismaClient();

        
        const existingUser = await prisma.users.findUnique({
            where: {
                id: userId
            }
        });

        if(!existingUser)
        {
            return res.status(400).json({
                error: "Invalid token"
            });
        }
        if(existingUser != null && existingUser.resetPasswordToken !== resetToken)
        {
            return res.status(400).json({
                error: "Invalid token"
            });
        }

        const previusPasswords = await prisma.previusPassword.findMany({
            where:{
                userId: existingUser.id
            },
            take: 3,
            orderBy: {
                createdAt: "desc"
            }
        });
        for(const prevPass of previusPasswords)
        {
            const isMatch = await bcrypt.compare(new_password, prevPass.password);
            if(isMatch)
            {
                return res.status(400).json({
                    error: "New password can't be one of the last 3 password."
                });
            }
        }
        
        const hasedPassword = await bcrypt.hash(new_password, 10);
        const updatedUser = await prisma.users.update({
            where: {
                id: userId
            },
            data: {
                password: hasedPassword,
                resetPasswordToken: null
            }
        });
        await prisma.previusPassword.create({
            data: {
                password: hasedPassword,
                userId: userId
            }
        });
        const allprevPass = await prisma.previusPassword.findMany({
            where:{
                userId: existingUser.id
            },
            orderBy: {
                createdAt: "desc"
            }
        });
        if(allprevPass > 3)
        {
            const passwordsToDelete = allprevPass.slice(3);
            await prisma.previusPassword.deleteMany({
                where: {
                    id: {
                        in: passwordsToDelete.map((pass) => pass.id)
                    }
                }
            });
        }
        if(updatedUser)
        {
            return res.status(200).json({
                message: "Password updated successfully"
            });
        }
        else
        {
            return res.status(500).json({
                error: "Something went wrong"
            });
        }
    }
    catch (error) {
        console.log(error);
        return res.status(500).json({
            error: "Something went wrong"
        });
    }
});

//protected routes
app.use(authMiddleware);

app.put("/api/change-password",async (req, res) => {
    try
    {
        const userId = req.user.id;
        const prisma = new PrismaClient();
        const { old_password, new_password } = req.body;
        const existingUser = await prisma.users.findUnique({
            where: {
                id: userId
            }
        });
        const isMatch = await bcrypt.compare(old_password, existingUser.password);
        if(!isMatch)
        {
            return res.status(400).json({
                error: "Old password is incorrect"
            });
        }

        const previusPasswords = await prisma.previusPassword.findMany({
            where:{
                userId: existingUser.id
            },
            take: 3,
            orderBy: {
                createdAt: "desc"
            }
        });
        for(const prevPass of previusPasswords)
        {
            const isMatch = await bcrypt.compare(new_password, prevPass.password);
            if(isMatch)
            {
                return res.status(400).json({
                    error: "New password can't be one of the last 3 password."
                });
            }
        }
        const hasedPassword = await bcrypt.hash(new_password, 10);
        const updatedUser = await prisma.users.update({
            where: {
                id: userId
            },
            data: {
                password: hasedPassword,
                resetPasswordToken: null
            }
        });
        await prisma.previusPassword.create({
            data: {
                password: hasedPassword,
                userId: userId
            }
        });
        const allprevPass = await prisma.previusPassword.findMany({
            where:{
                userId: existingUser.id
            },
            orderBy: {
                createdAt: "desc"
            }
        });
        if(allprevPass > 3)
        {
            const passwordsToDelete = allprevPass.slice(3);
            await prisma.previusPassword.deleteMany({
                where: {
                    id: {
                        in: passwordsToDelete.map((pass) => pass.id)
                    }
                }
            });
        }
        if(updatedUser)
        {
            return res.status(200).json({
                message: "Password updated successfully"
            });
        }
        else
        {
            return res.status(500).json({
                error: "Something went wrong"
            });
        }
    }
    catch (error) {
        console.log(error);
        return res.status(500).json({
            error: "Something went wrong"
        });
    }
})

app.post("/api/posts", async (req, res) => {
    try
    {
        const userId = req.user.id;
        const { title, content, status } = req.body;
        if(!title || !content)
        {
            return res.status(400).json({
                error: "Please fill all the fields"
            });
        }
        const prisma = new PrismaClient();
        const newPost = await prisma.posts.create({
            data: {
                title,
                content,
                status,
                userId: userId
            }
        });
        return res.status(201).json({
            message: "Post created successfully",
            post: newPost
        });
    }
    catch (error) {
        console.log(error);
        return res.status(500).json({
            error: "Something went wrong"
        });
    }
})

app.get("/api/me/posts", async (req, res) => {
    try
    {
        const userId = req.user.id;
        const prisma = new PrismaClient();
        const allPosts = await prisma.posts.findMany({
            where: {
                userId: userId,
            }
        });
        return res.status(200).json({
            posts: allPosts
        });
    }
    catch (error) {
        console.log(error);
        return res.status(500).json({
            error: "Something went wrong"
        });
    }
})

app.get("/api/me/posts/draft", async (req, res) => {
    try
    {
        const userId = req.user.id;
        const prisma = new PrismaClient();
        const allPosts = await prisma.posts.findMany({
            where: {
                userId: userId,
                status: "DRAFT"
            }
        });
        return res.status(200).json({
            posts: allPosts
        });
    }
    catch (error) {
        console.log(error);
        return res.status(500).json({
            error: "Something went wrong"
        });
    }
})

app.get("/api/posts", async (req, res) => {
    try
    {
        const prisma = new PrismaClient();
        const allPosts = await prisma.posts.findMany({
            where: {
                status: "PUBLIC"
            },
            include:{
                user: {
                    select: {
                        username: true,
                        email: true
                    }
                }
            }
        });
        return res.status(200).json({
            posts: allPosts
        });
    }
    catch (error) {
        console.log(error);
        return res.status(500).json({
            error: "Something went wrong"
        });
    }
})

app.get("/api/posts/:id", async (req, res) => {
    try
    {
        const postId = req.params.id;
        const prisma = new PrismaClient();
        const post = await prisma.posts.findUnique({
            where: {
                id: postId,
                status: "PUBLIC"
            }
        });
        return res.status(200).json({
            post: post
        });
    }
    catch (error) {
        console.log(error);
        return res.status(500).json({
            error: "Something went wrong"
        });
    }
})

app.put("/api/posts/:id", async (req, res) => {
    try
    {
        const postId = req.params.id;
        const prisma = new PrismaClient();
        const userId = req.user.id;

        const { title, content, status } = req.body;
        
        const post = await prisma.posts.findUnique({
            where: {
                id: postId,
            }
        });
        if(!post)
        {
            return res.status(400).json({
                error: "Post does not exist"
            });
        }
        const updatedPost = await prisma.posts.update({
            where: {
                id: postId
            },
            data: {
                ...(title && {title}), 
                ... (content && {content}), 
                ... (status && {status}) 
            }
        });
        return res.status(200).json({
            message: "Post updated successfully",
            post: updatedPost
        });
    }
    catch (error) {
        console.log(error);
        return res.status(500).json({
            error: "Something went wrong"
        });
    }
})

app.delete("/api/posts/:id", async (req, res) => {
    try
    {
        const postId = req.params.id;
        const prisma = new PrismaClient();
        const userId = req.user.id;
        const post = await prisma.posts.findUnique({
            where: {
                id: postId,
            }
        });
        if(!post)
        {
            return res.status(400).json({
                error: "Post does not exist"
            });
        }
        const deletedPost = await prisma.posts.delete({
            where: {
                id: postId
            }
        });
        return res.status(200).json({
            message: "Post deleted successfully",
            post: deletedPost
        });
    }
    catch (error) {
        console.log(error);
        return res.status(500).json({
            error: "Something went wrong"
        });
    }
})

app.listen(3000, () => {
    console.log("Server is running on port 3000");
});