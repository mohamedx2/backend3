const User = require('../models/user.model');
const Article = require('../models/article.model');
let controller = {}
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

controller.verify= async (req,res,next)=>{
  const token = req.headers.authorization.split(" ")[1];
  if (!token) return res.status(401).send({ message: 'Unauthorized' });
  try {
    const decodedToken = await jwt.verify(token, process.env.JWT_SECRET);
    req.decodedToken=decodedToken
    next()
  } catch (error) {
    return res.send({message:'Unauthorized from verify'})
  }
}


controller.signUp = async (req, res) => {
  try {
    // Check if user already exists
    const existingUser = await User.findOne({ email: req.body.email });

    // If user already signed up, don't allow them to make another account
    if (existingUser) {
      return res.send({ message: "already signed up", success: false });
    }

    // Hash the password with bcrypt
    const hashedPassword = await bcrypt.hash(req.body.password, 10);

    // Replace the plain text password with the hashed one
    req.body.password = hashedPassword;

    // Create a new user and save
    const newUser = new User(req.body);

    // Save the new user to the database
    const savedUser = await newUser.save();

    // Generate JWT token for the user
    const token = jwt.sign(
      { userId: savedUser._id },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    // Return success response with the saved user and token
    return res.send({
      success: true,
      message: "Created new user",
      data: {
        user: savedUser,
        token: token,
      },
    });
  } catch (error) {
    console.error(error);
    return res.status(500).send("An error occurred while signing up.");
  }
};

controller.update = async (req, res) => {
  try {
    req.body.password=await bcrypt.hash(req.body.password, 10)
    const  updatedUser= await User.findByIdAndUpdate(
      req.decodedToken.userId,
      req.body,
      { new: true },
    );
    res.send({ updatedUser, message:"user updated with succes", success:true });
  } catch (error) {
    return res.send({
      message: "An error occurred while updating user.",
    });
  }
};
controller.login = async (req, res) => {
  try {
    // Check if user exists
    const existingUser = await User.findOne({ email: req.body.email });

    // If user doesn't exist, return error response
    if (!existingUser) {
      return res.send({ message: "user not found", success: false });
    }
    // Compare the password with bcrypt
    const isPasswordCorrect = await bcrypt.compare(req.body.password, existingUser.password);
    // If password is incorrect, return error response
    if (!isPasswordCorrect) {
      return res.send({ message: 'invalid credentials', success: false });
    }

    // Generate JWT token for the user
    const token = jwt.sign(
      { userId: existingUser._id},
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    // Return success response with the generated token
    return res.send({
      success: true,
      message: "Logged in successfully",
      data: {
        user: existingUser,
        token: token,
      },
    });
  } catch (error) {
    console.error(error);
    return res.status(500).send("An error occurred while logging in.");
  }
};

controller.updateArticle = async (req, res) => {

  try {
    // Find the article by id
    const article = await Article.findById(req.params.id);

    // Check if the article exists
    if (!article) {
      return res.status(404).send({ message: "Article not found" });
    }
    if (req.decodedToken.userId !== article.poster.toString()) {
      return res.status(401).send({ message: "Unauthorized" });
    }

    // Check if the article belongs to the user in the JWT token

    // Update the article and return success response
    const updatedArticle = await Article.findByIdAndUpdate(
      req.params.id,
      req.body,
      { new: true }
    );
    res.json({ updatedArticle, message: 'Updated successfully' });
  } catch (error) {
    console.error(error);
    return res.status(500).send("An error occurred while updating article.");
  }
};

controller.createArticle = async (req, res) => {

  try {

    // Create a new article with author id from the JWT token
    const newArticle = new Article({
      ...req.body,
      poster: req.decodedToken.userId
    });

    // Save the new article to the database
    const savedArticle = await newArticle.save();

    // Return success response with the saved article
    res.json({
      success: true,
      message: "Created new article",
      data: savedArticle
    });
  } catch (error) {
    console.error(error);
    return res.status(500).send("An error occurred while creating article.");
  }
};
controller.showArticles = async (req, res) => {
  try {
    const allArticle = await Article.find();
    res.json(allArticle);
  } catch (error) {
    res.status(500).send(error);
  }
};

controller.myArticles = async (req, res) => {
  try {
    // Find all articles posted by the user
    const allArticle = await Article.find({ poster: req.decodedToken.userId });
    res.json(allArticle);
  } catch (error) {
    console.error(error);
    return res.status(500).send("An error occurred while fetching articles.");
  }
};


controller.deleteArticle = async (req, res) => {

  try {

    // Find the article by id
    const article = await Article.findById(req.params.id);

    // Check if the article exists
    if (!article) {
      return res.status(404).send({ message: "Article not found" });
    }

    // Check if the article belongs to the user in the JWT token
    if (req.decodedToken.userId !== article.poster.toString()) {
      return res.status(401).send({ message: "Unauthorized" });
    }

    // Delete the article and return success response
    await Article.findByIdAndDelete(req.params.id);
    res.status(200).json({ message: 'Article deleted successfully!' });
  } catch (error) {
    console.error(error);
    return res.status(500).send("An error occurred while deleting article.");
  }
};

module.exports = controller
