import express from "express";
import fetch from "node-fetch";
import "dotenv/config";
import path from "path";
import mongoose from "mongoose";
import jwt from "jsonwebtoken";
import multer from "multer";
import cors from "cors";
import nodemailer from 'nodemailer';


const port = 4000;
const app = express();

const corsOptions = {
  origin: ['https://vinotie.com', 'http://vinotie.com', 'http://localhost:3000'], // Add all domains that need access
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD'], // Specify allowed methods
  allowedHeaders: ['Content-Type', 'Authorization'], // Specify allowed headers
  credentials: true, // Enable credentials if your frontend needs to send cookies or authentication info
  optionsSuccessStatus: 204 // Some legacy browsers (IE11, various SmartTVs) choke on 204
};

const { PAYPAL_CLIENT_ID, PAYPAL_CLIENT_SECRET, PORT = 8888 } = process.env;
const base = "https://api-m.sandbox.paypal.com";


app.use(express.json());
app.use(cors(corsOptions));

// Database Connection With MongoDB

mongoose.connect("mongodb+srv://arielrubin25:LjzK9OCBWzJACHDh@cluster1.kki2pd6.mongodb.net/");
// paste your mongoDB Connection string above with password
// password should not contain '@' special character

//Image Storage Engine 
const storage = multer.diskStorage({
    destination: './upload/images',
    filename: (req, file, cb) => {
      console.log(file);
        return cb(null, `${file.fieldname}_${Date.now()}${path.extname(file.originalname)}`)
    }
})
const upload = multer({storage: storage})
app.post("/upload", upload.single('product'), (req, res) => {
    res.json({
        success: 1,
        image_url: `http://localhost:4000/images/${req.file.filename}`
    })
})
app.use('/images', express.static('upload/images'));

// MiddleWare to fetch user from database
const fetchuser = async (req, res, next) => {
  const token = req.header("auth-token");
  if (!token) {
    res.status(401).send({ errors: "Please authenticate using a valid token" });
  }
  try {
    const data = jwt.verify(token, "secret_ecom");
    req.user = data.user;
    next();
  } catch (error) {
    res.status(401).send({ errors: "Please authenticate using a valid token" });
  }
};
// Example of a backend endpoint to fetch product details
app.get('/api/products/:id', async (req, res) => {
  try {
      const product = await Product.findById(req.params.id);
      if (product) {
          res.json(product);
      } else {
          res.status(404).send('Product not found');
      }
  } catch (error) {
      res.status(500).send('Server error');
  }
});

// Configure Nodemailer to use Gmail
const transporter = nodemailer.createTransport({
  host: 'mail.vinotie.com', // Replace with your mail server's SMTP host
  port: 465,                  // Commonly 587 for STARTTLS or 465 for SSL
  secure: true,              // True if port is 465, false for port 587
  auth: {
    user: 'arieltest@vinotie.com', // Your email username
    pass: process.env.EMAIL_PASSWORD
  },
  tls: {
    // Do not fail on invalid certs (set this to true in production)
    rejectUnauthorized: true
  }
});

// Function to send email
const sendEmail = async (options) => {
  const mailOptions = {
    from: process.env.EMAIL_USERNAME,
    to: options.to,
    subject: options.subject,
    text: options.text,
    html: options.html,
  };

  transporter.sendMail(mailOptions, function(error, info){
    if (error) {
      console.log('Error sending email: ', error);
    } else {
      console.log('Email sent: ' + info.response);
    }
  });
}

// Schema for creating user model
const Users = mongoose.model("Users", {
  name: {
    type: String,
  },
  email: {
    type: String,
    unique: true,
  },
  password: {
    type: String,
  },
  cartData: {
    type: Object,
  },
  date: {
    type: Date,
    default: Date.now,
  },
});

// Schema for creating Product
const Product = mongoose.model("Product", {
  id: {
    type: Number,
    required: true,
  },
  name: {
    type: String,
    required: true,
  },
  image: {
    type: String,
    required: true,
  },
  category: {
    type: String,
    required: true,
  },
  new_price: {
    type: Number
  },
  old_price: {
    type: Number
  },
  date: {
    type: Date,
    default: Date.now,
  },
  avilable: {
    type: Boolean,
    default: true,
  },
});

app.get("/", (req, res) => {
  res.send("Root");
});
//orderschema for storing the order details
const orderSchema = new mongoose.Schema({
  shippingDetails: {
    name: { full_name: String },
    address: {
      address_line_1: String,
      address_line_2: String,
      admin_area_2: String,
      admin_area_1: String,
      postal_code: String,
      country_code: String
    }
  },
  products: [{
    name: String,
    unit_amount: {
      currency_code: String,
      value: String
    },
    quantity: String
  }],
  date: {
    type: Date,
    default: Date.now
  }
});

const Order = mongoose.model('Order', orderSchema);

//Create an endpoint at ip/login for login the user and giving auth-token
app.post('/login', async (req, res) => {
  console.log("Login");
    let success = false;
    let user = await Users.findOne({ email: req.body.email });
    if (user) {
        const passCompare = req.body.password === user.password;
        if (passCompare) {
            const data = {
                user: {
                    id: user.id
                }
            }
			success = true;
      console.log(user.id);
			const token = jwt.sign(data, 'secret_ecom');
			res.json({ success, token });
        }
        else {
            return res.status(400).json({success: success, errors: "please try with correct email/password"})
        }
    }
    else {
        return res.status(400).json({success: success, errors: "please try with correct email/password"})
    }
})

//Create an endpoint at ip/auth for regestring the user in data base & sending token
app.post('/signup', async (req, res) => {
  console.log("Sign Up");
        let success = false;
        let check = await Users.findOne({ email: req.body.email });
        if (check) {
            return res.status(400).json({ success: success, errors: "existing user found with this email" });
        }
        let cart = {};
          for (let i = 0; i < 300; i++) {
          cart[i] = 0;
        }
        const user = new Users({
            name: req.body.username,
            email: req.body.email,
            password: req.body.password,
            cartData: cart,
        });
        await user.save();
        const data = {
            user: {
                id: user.id
            }
        }
        
        const token = jwt.sign(data, 'secret_ecom');
        success = true; 
        res.json({ success, token })
    })

app.get("/allproducts", async (req, res) => {
	let products = await Product.find({});
  console.log("All Products");
    res.send(products);
});

app.get("/newcollections", async (req, res) => {
	let products = await Product.find({});
  let arr = products.slice(1).slice(-8);
  console.log("New Collections");
  res.send(arr);
});

app.get("/popularinwomen", async (req, res) => {
	let products = await Product.find({});
  let arr = products.splice(0,  4);
  console.log("Popular In Women");
  res.send(arr);
});

//Create an endpoint for saving the product in cart
app.post('/addtocart', fetchuser, async (req, res) => {
	console.log("Add Cart");
    let userData = await Users.findOne({_id:req.user.id});
    userData.cartData[req.body.itemId] += 1;
    await Users.findOneAndUpdate({_id:req.user.id}, {cartData:userData.cartData});
    res.send("Added")
  })

  //Create an endpoint for saving the product in cart
app.post('/removefromcart', fetchuser, async (req, res) => {
	console.log("Remove Cart");
    let userData = await Users.findOne({_id:req.user.id});
    if(userData.cartData[req.body.itemId]!=0)
    {
      userData.cartData[req.body.itemId] -= 1;
    }
    await Users.findOneAndUpdate({_id:req.user.id}, {cartData:userData.cartData});
    res.send("Removed");
  })

  //Create an endpoint for saving the product in cart
app.post('/getcart', fetchuser, async (req, res) => {
  console.log("Get Cart");
  let userData = await Users.findOne({_id:req.user.id});
  res.json(userData.cartData);

  })


app.post("/addproduct", async (req, res) => {
  let products = await Product.find({});
  let id;
  if (products.length>0) {
    let last_product_array = products.slice(-1);
    let last_product = last_product_array[0];
    id = last_product.id+1;
  }
  else
  { id = 1; }
  const product = new Product({
    id: id,
    name: req.body.name,
    image: req.body.image,
    category: req.body.category,
    new_price: req.body.new_price,
    old_price: req.body.old_price,
  });
  console.log(product);
  await product.save();
  console.log("Saved");
  res.json({success:true,name:req.body.name})
});

app.post("/removeproduct", async (req, res) => {
  const product = await Product.findOneAndDelete({ id: req.body.id });
  console.log("Removed");
  res.json({success:true,name:req.body.name})
});

app.listen(port, (error) => {
  if (!error) console.log("Server Running on port " + port);
  else console.log("Error : ", error);
});



//Paypal Integration
// host static files
app.use(express.static("client"));

// parse post params sent in body in json format
app.use(express.json());

/**
 * Generate an OAuth 2.0 access token for authenticating with PayPal REST APIs.
 * @see https://developer.paypal.com/api/rest/authentication/
 */
const generateAccessToken = async () => {
  try {
    if (!PAYPAL_CLIENT_ID || !PAYPAL_CLIENT_SECRET) {
      throw new Error("MISSING_API_CREDENTIALS");
    }
    const auth = Buffer.from(
      PAYPAL_CLIENT_ID + ":" + PAYPAL_CLIENT_SECRET
    ).toString("base64");
    const response = await fetch(`${base}/v1/oauth2/token`, {
      method: "POST",
      body: "grant_type=client_credentials",
      headers: {
        Authorization: `Basic ${auth}`,
      },
    });

    const data = await response.json();
    return data.access_token;
  } catch (error) {
    console.error("Failed to generate Access Token:", error);
  }
};

async function handleResponse(response) {
  try {
    const jsonResponse = await response.json();
    return {
      jsonResponse,
      httpStatusCode: response.status,
    };
  } catch (err) {
    const errorMessage = await response.text();
    throw new Error(errorMessage);
  }
}

/**
 * Create an order to start the transaction.
 * @see https://developer.paypal.com/docs/api/orders/v2/#orders_create
 */
const createOrder = async (cart) => {
  const accessToken = await generateAccessToken();
  const url = `${base}/v2/checkout/orders`;

  const payload = {
      intent: "CAPTURE",
      purchase_units: [{
        amount: {
            currency_code: "USD",
            value: cart.total.toString(),
            breakdown: {
                item_total: { 
                    currency_code: "USD",
                    value: cart.items.reduce((sum, item) => sum + (item.new_price * item.quantity), 0).toFixed(2)
                }
            }
        },
        items: cart.items.map(item => ({
            name: item.name,
            sku: item.id.toString(),  // Ensure this corresponds to an 'id' attribute in your database
            unit_amount: {
                currency_code: "USD",
                value: item.new_price.toString(),
            },
            quantity: item.quantity.toString(),
        })),
        shipping: {
            name: {
                full_name: "Customer Name"  // Ensure this is dynamically set
            },
            address: {
                address_line_1: '123 ABC St.',
                address_line_2: 'Unit 1',
                admin_area_2: 'City',
                admin_area_1: 'State',
                postal_code: '12345',
                country_code: 'US'
            }
        }
    }],
      application_context: {
          shipping_preference: "SET_PROVIDED_ADDRESS"
      }
  };
// Log the payload to console
console.log("Payload to PayPal:", JSON.stringify(payload, null, 2));
  const response = await fetch(url, {
      method: "POST",
      headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${accessToken}`,
      },
      body: JSON.stringify(payload),
  });

  return handleResponse(response);
};

// createOrder route
app.post("/api/orders", async (req, res) => {
  try {
    // use the cart information passed from the front-end to calculate the order amount detals
    const { cart } = req.body;
    const { jsonResponse, httpStatusCode } = await createOrder(cart);
    res.status(httpStatusCode).json(jsonResponse);
  } catch (error) {
    console.error("Failed to create order:", error);
    res.status(500).json({ error: "Failed to create order." });
  }
}); 
/**
 * Capture payment for the created order to complete the transaction.
 * @see https://developer.paypal.com/docs/api/orders/v2/#orders_capture
 */
const captureOrder = async (orderID) => {
  const accessToken = await generateAccessToken();
  const url = `${base}/v2/checkout/orders/${orderID}/capture`;

  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${accessToken}`,
      // Uncomment one of these to force an error for negative testing (in sandbox mode only).
      // Documentation:
      // https://developer.paypal.com/tools/sandbox/negative-testing/request-headers/
      // "PayPal-Mock-Response": '{"mock_application_codes": "INSTRUMENT_DECLINED"}'
      // "PayPal-Mock-Response": '{"mock_application_codes": "TRANSACTION_REFUSED"}'
      // "PayPal-Mock-Response": '{"mock_application_codes": "INTERNAL_SERVER_ERROR"}'
    },
  });
  const jsonResponse = await handleResponse(response);
  return jsonResponse;  // This should include the full response with payer details
};

// captureOrder route
app.post("/api/orders/:orderID/capture", async (req, res) => {
  try {
    const { orderID } = req.params;
    const { jsonResponse, httpStatusCode } = await captureOrder(orderID);

    // Assume jsonResponse contains necessary order details
    if (jsonResponse.httpStatusCode === 201 && jsonResponse.jsonResponse.payer) {
      const customerEmail = jsonResponse.jsonResponse.payer.email_address; // Extract email

      // Send confirmation email to the customer
      sendEmail({
        to: customerEmail, // Use extracted email
        subject: 'Order Confirmation',
        html: `<h1>Thank you for your purchase!</h1><p>Your order has been processed successfully.</p>`
      });

      sendEmail({
        to: 'arieltest@vinotie.com', // Your email
        subject: 'New Order Received',
        html: `<h1>New Order Details</h1><p>Order ID: ${orderID}</p>`
      });
    

    res.status(201).json(jsonResponse.jsonResponse);
    } else {
      res.status(jsonResponse.httpStatusCode).json(jsonResponse.jsonResponse);
    }
  } catch (error) {
    console.error("Failed to capture order:", error);
    res.status(500).json({ error: "Failed to capture order." });
  }
});

// serve index.html
app.get("/", (req, res) => {
  res.sendFile(path.resolve("./checkout.html"));
});

app.post('/api/save-order', async (req, res) => {
  
  const { shippingDetails, products } = req.body;
  
  const newOrder = new Order({
    shippingDetails,
    products
  });

  try {
    await newOrder.save();
    console.log("Order saved:", newOrder);
    res.json({ message: 'Order received and is being processed', orderId: newOrder._id });
  } catch (error) {
    console.error("Error saving order:", error);
    res.status(500).json({ error: 'Failed to save order.' });
  }
});


app.listen(PORT, () => {
  console.log(`Node server listening at http://localhost:${PORT}/`);
}); 

