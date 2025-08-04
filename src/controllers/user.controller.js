import { response } from "express"
import {asyncHandler} from "../utils/asyncHandler.js"
import {ApiError} from "../utils/ApiError.js"
import {User} from "../models/user.model.js"
import {uploadOnCloudinary} from "../utils/cloudinary.js"
import { ApiResponse } from "../utils/ApiResponse.js"

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

export {registerUser}