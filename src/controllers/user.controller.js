import { response } from "express"
import {asyncHandler} from "../utils/asyncHandler.js"
import {ApiError} from "../utils/ApiError.js"
import {User} from "../models/user.model.js"
import {uploadOnCloudinary} from "../utils/cloudinary.js"
import { ApiResponse } from "../utils/ApiResponse.js"
import jwt from "jsonwebtoken"
import mongoose from "mongoose"

const generateAccessAndRefreshToken = async(userId) => 
{
    try {

        const user = await User.findById(userId)
        const accessToken = user.generateAccessToken()
        const refreshToken = user.generateRefreshToken()
        user.refreshToken = refreshToken
        await user.save({validateBeforeSave: false})
        return {accessToken, refreshToken}
    
    } catch (error) {
        throw new ApiError(500, "Something went wrong while generating access and refresh token")
    }
}

const registerUser = asyncHandler( async(req, res) => {
    //1. Get user detailds from frontend
    const {fullname, username, email, password} = req.body
    console.log("Email: ", email)

    //2. Validation-Not empty
    if(
        [fullname, username, email, password].some((field) => field?.trim() === "")
    ){
        throw new ApiError(400, "All fields are required")
    }

    //3. Check if user already empty: username, email
    const existedUser = await User.findOne({
        $or: [{ username }, { email }]
    })

    if(existedUser){
        throw new ApiError(409, "User with username or email already exists")
    }

    //4. Check for images, avatar
    const avatarLocalPath = req.files?.avatar[0]?.path
    const coverImageLocalPath = req.files?.coverImage[0]?.path
    if(!avatarLocalPath){
        throw new ApiError(400, "Avatar is required")
    }

    //5. Upload them on cloudinary, avatar
    const avatar = await uploadOnCloudinary(avatarLocalPath)
    const coverImage = await uploadOnCloudinary(coverImageLocalPath)
    if(!avatarLocalPath){
        throw new ApiError(400, "Avatar is required")
    }

    //6. Create user object - entry in db
    const user = await User.create({
        fullname,
        avatar: avatar.url,
        coverImage: coverImage?.url||"",
        email,
        password,
        username: username.toLowerCase()
    })

    //7. Remove password and refresh token from response 
    const createdUser = await User.findById(user._id).select("-password -refreshToken")

    //8. Check for user Creation
    if(!createdUser){
        throw new ApiError(500, "Something went wrong while registering the user")
    }

    //9. Return response
    return res.status(200).json(
        new ApiResponse(200, createdUser, "User registered successfully!!")
    )
} )

const loginUser = asyncHandler( async(req,res) => {
    // 1. req body -> data
    const {username, email, password} = req.body

    // 2. username or email
    if(!(username || email)){
        throw new ApiError(400, "Email or username required")
    }
    
    //3. find the user
    const user = await User.findOne({
        $or: [{username},{email}]
    })

    if(!user){
        throw new ApiError(404, "User does not exist")
    }

    //4. password check
    const isPasswordValid = await user.isPasswordCorrect(password)
    if(!isPasswordValid){
        throw new ApiError(401, "Invalid User Credentials")
    }

    //5. access and refresh token
    const {accessToken, refreshToken} = await generateAccessAndRefreshToken(user._id)

    const loggedInUser = await User.findById(user._id).select("-password -refreshToken")

    //6. send cookie
    const options = {
        httpOnly: true,
        secure: true
    }

    console.log("User:", user);
    console.log("AccessToken Function:", typeof user.generateAccessToken);
    console.log("AccessToken:", accessToken);
    console.log("RefreshToken:", refreshToken);
    console.log("JWT Secret:", process.env.ACCESS_TOKEN_SECRET);


    return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken, options)
    .json(
        new ApiResponse(
            200,
            {
                user: loggedInUser, refreshToken, accessToken
            },
            "User loggedIn Successfully"
        )
    )
} )

const logoutUser = asyncHandler( async(req, res) => {
    await User.findByIdAndUpdate(
        req.user._id,
        {
            $set: {
                refreshToken: undefined
            }
        },
        {
            new: true
        }
    )
    
    const options = {
        httpOnly: true,
        secure: true
    }

    return res
    .status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(new ApiResponse(200, {}, "User Logged out"))

} )

const refreshAccessToken = asyncHandler( async(req,res) => {
    const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken

    if(!incomingRefreshToken){
        throw new ApiError(401, "Unauthorized request")
    }

    try {
        const decodedToken = jwt.verify(incomingRefreshToken, process.env.REFRESH_TOKEN_SECRET)
    
        const user = await User.findById(decodedToken?._id);
    
        if(!user){
            throw new ApiError(401, "Invalid Refresh Token")
        }
    
        if(incomingRefreshToken !== user?.refreshToken){
            throw new ApiError(401, "Refresh Token is expired or used")
        }
    
        const options = {
            httpOnly: true,
            secure: true
        }
    
        const{accessToken, newRefreshToken} = await generateAccessAndRefreshToken(user._id)
    
        return res
        .status(200)
        .cookie("accessToken", accessToken, options)
        .cookie("refreshToken", newRefreshToken, options)
        .json(
            new ApiResponse(
                200,
                {accessToken, refreshToken: newRefreshToken},
                "Access Token refreshed"
            )
        )
    } catch (error) {
        throw new ApiError(401, error?.message || "Invalid refresh token")
    }

} )

const changeCurrentPassword = asyncHandler( async(req, res) => {
    const {oldPassword, newPassword} = req.body
    const user = await User.findById(req.user?._id)
    const isPasswordCorrect = await user.isPasswordCorrect(oldPassword)
    if(!isPasswordCorrect){
        throw new ApiError(400, "Old Password is incorrect")
    }
    user.password = newPassword
    await user.save({validateBeforeSave: true})

    return res
    .status(200)
    .json(new ApiResponse(200, "Password changed successfully"))
} )

const getCurrentUser = asyncHandler( async(req, res) => {
    return res
    .status(200)
    .json(200, res.user, "Current user fetched successfully")
} )

const updateAccountDetails = asyncHandler( async(req, res) => {
    const {fullname, email} = res.body

    if( ! fullname || email ){
        throw new ApiError(400, "All fields are required")
    }

    const user = await User.findByIdAndUpdate(
        res.user?._id,
        {
            $set:{
                fullname: fullname,
                email: email // both can alo be written inly fullname and email
            }
        },
        {new: true}
    ).select("-password")

    return res
    .status(200)
    .json(ApiResponse(200, user, "User details updated successfully"))
} )

const updateUserAvatar = asyncHandler( async(req, res) => {
    const avatarLocalPath = req.file?.path

    if(!avatarLocalPath){
        throw new ApiError(400, "Avatar File is missing")
    }

    const avatar = await uploadOnCloudinary(avatarLocalPath)

    if(!avatar.url){
        throw new ApiError(400, "Error while uploading Avatar")
    }

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set:{
                avatar: avatar.url
            }
        },
        {
            new: true
        }
    ).select("-password")

    return res
    .status(200)
    .json(
        new ApiResponse(200, user, "Avatar uploaded successfully")
    )

} )

const updateUserCoverImage = asyncHandler( async(req, res) => {
    const coverImageLocalPath = req.file?.path

    if(!coverImageLocalPath){
        throw new ApiError(400, "Cover Image File is missing")
    }

    const coverImage = await uploadOnCloudinary(coverImageLocalPath)

    if(!coverImage.url){
        throw new ApiError(400, "Error while uploading Cover Image")
    }

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set:{
                coverImage: coverImage.url
            }
        },
        {
            new: true
        }
    ).select("-password")

    return res
    .status(200)
    .json(
        new ApiResponse(200, user, "Cover Image uploaded successfully")
    )

} )

const getUserChannelProfile = asyncHandler( async(req, res) => {
    const {username} = req.params
    if(!username){
        throw new ApiError(400, "Username is missing")
    }

    const channel = await User.aggregate(
        [
            {
                $match: {
                    username: username?.toLowerCase()
                }
            },
            {
                $lookup: {
                    from: "subscriptions",
                    localField: "_id",
                    foreignField: "channel",
                    as: "subscribers"
                }
            },
            {
                $lookup: {
                    from: "subscriptions",
                    localField: "_id",
                    foreignField: "subscriber",
                    as: "subscribedTo"
                }
            },
            {
                $addFields: {
                    subscribersCount: {
                        $size: "$subscribers"
                    },
                    channelsSubscribedToCount: {
                        $size: "$subscribedTo"
                    },
                    isSubscribed: {
                        $cond: {
                            if: {
                                $in: [req.user?._id, "$subscribers.subscriber"]
                            },
                            then: true,
                            else: false
                        }
                    }
                }
            },
            {
                $project: {
                    fullname: 1,
                    username: 1,
                    avatar: 1,
                    coverImage: 1,
                    email: 1,
                    subscribersCount: 1,
                    channelsSubscribedToCount: 1,
                    isSubscribed: 1
                }
            }
        ]
    )

    if(!channel?.length){
        throw new ApiError(404, "Channel does not exists")
    }

    return res
    .status(200)
    .json(new ApiResponse(200, channel[0], "User channel fetched successfully"))
} )

const getWatchHistory = asyncHandler( async(req, res) => {
    const user = await User.aggregate(
        [
            {
                $match: {
                    _id: new mongoose.Types.ObjectId(req.user._id)
                }
            },
            {
                $lookup: {
                    from: "videos",
                    localField: "watchHistory",
                    foreignField: "_id",
                    as: "watchHistory",
                    pipeline: [
                        {
                            $lookup: {
                                from: "users",
                                localField: "owner",
                                foreignField: "_id",
                                as: "owner",
                                pipeline: [
                                    {
                                        $project: {
                                            fullname: 1,
                                            username: 1,
                                            avatar: 1
                                        }
                                    }
                                ]
                            }
                        },
                        {
                            $addFields: {
                                owner: {
                                    $first: "$owner"
                                }
                            }
                        }
                    ]
                }
            }
        ]
    )

    return res
    .status(200)
    .json(new ApiResponse(200, user[0].watchHistory, "Watch History Fetched Successfully"))
} )

export {
    registerUser,
    loginUser,
    logoutUser,
    refreshAccessToken,
    changeCurrentPassword,
    getCurrentUser,
    updateAccountDetails,
    updateUserAvatar,
    updateUserCoverImage,
    getUserChannelProfile,
    getWatchHistory
}