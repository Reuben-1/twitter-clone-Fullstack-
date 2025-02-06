import User from "../models/user.model.js";
import bcrypt from "bcryptjs";
import { generateTokenAndSetCookie } from "../lib/utils/generateToken.js";

export const signup = async (req,res) =>{
    try {
        const {fullName, username, email, password} = req.body;

        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

        if (!emailRegex.test(email)) {
            return res.status(400).json({error: "Invalid email format",});
        }

        const existingUser = await User.findOne({username}); // should be username:username but since their the same just username will suffice
        if (existingUser) {
            return res.status(400).json({error: "Username is already taken",});
        }

        const existingEmail = await User.findOne({email}); // should be username:username but since their the same just username will suffice
        if (existingEmail) {
            return res.status(400).json({error: "Email is already in use",});
        }

        if (password.length < 8) {
            return res.status(400).json({error: "Password must contain atleast 8 characters"});
        }
        const salt = await bcrypt.genSalt(10);
        const hashedPassword= await bcrypt.hash(password,salt);

        const newUser = new User({
            fullName,
            username,
            email,
            password:hashedPassword
        });

        if(newUser){
            generateTokenAndSetCookie(newUser._id,res);
            await newUser.save();

            res.status(201).json({
                _id: newUser._id,
                fullName: newUser.fullName,
                username: newUser.username,
                email: newUser.email,
                followers: newUser.followers,
                following: newUser.following,
                profileImg:newUser.profileImg,
                coverImg:newUser.coverImg,
            })
        }else{
            res.status(400).json({error: "Invalid user data"});
        }
    } catch (error) {
        console.log("Error in signup controller", error. message);
        res.status(500).json({error: "Internal Server Error"});
    }
}

export const login = async (req,res) =>{
   try {
    const {email, password} = req.body;

    const user = await User.findOne({email});
    if (!user) {
        return res.status(400).json({error: "Email does not exist",});
    }

    const isPasswordCorrect = await bcrypt.compare(password, user?.password || "");
    if (!isPasswordCorrect) {
        return res.status(400).json({error: "Password does not match",});
    }

    generateTokenAndSetCookie(user._id, res);

    res.status(201).json({
        _id: user._id,
        fullName: user.fullName,
        username: user.username,
        email: user.email,
        followers: user.followers,
        following: user.following,
        profileImg: user.profileImg,
        coverImg: user.coverImg,
    })
   } catch (error) {
        console.log("Error in login controller", error. message);
        res.status(500).json({error: "Internal Server Error"});
   }
}

export const logout = async (req,res) =>{
    try {
        res.cookie("jwt","",{maxAge:0});
        res.status(200).json({message:"Logged out successfully"})
    } catch (error) {
        console.log("Error in login controller", error. message);
        res.status(500).json({error: "Internal Server Error"});
    }
}

export const getMe = async (req,res) => {
    try {
        const user = await User.findById(req.user._id).select("-password");
        res.status(200).json(user);
    } catch (error) {
        console.log("Error in getMe controller", error. message);
        res.status(500).json({error: "Internal Server Error"});
    }
}