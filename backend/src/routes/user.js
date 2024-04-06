import { Router } from "express"
import { getCurrentUser, loginUser, logoutUser, refreshAccessToken, registerUser } from "../controllers/user.js"
import {upload} from "../middlewares/multer.js"
import { verifyJWT } from "../middlewares/auth.js"

const userRouter = Router()

userRouter.route("/register").post(registerUser)

userRouter.route("/login").post(loginUser)

userRouter.route("/logout").post(verifyJWT, logoutUser)
userRouter.route("/refresh-token").post(refreshAccessToken)
userRouter.route("/current-user").get(verifyJWT, getCurrentUser)


export default userRouter