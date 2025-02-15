const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const swaggerJsdoc = require("swagger-jsdoc");
const swaggerUi = require("swagger-ui-express");

const options = {
	definition: {
		swagger: "2.0",
		title: "Testing",
		info: {
			title: "Testing",
			description: "POS-SERVER API Documentation For Testing"
		},
		schemes: ["http"]
	},
	apis: ["./routers/*.js"],
};

const PORT = 3010;
const app = express();

const specs = swaggerJsdoc(options);
app.use(
	"/docs",
	swaggerUi.serve,
	swaggerUi.setup(specs, { explorer: true })
);

app.use(bodyParser.json());
app.use(cors());

app.get("/", (req, res) => {
	res.send("API Ready To GO!");
});

// Impor rute autentikasi
const authRoutes = require('./auth/authRoutes.js');
const { authenticateToken } = require ("./auth/authController.js")

// Gunakan rute autentikasi
app.use('/auth', authRoutes);

const product = require("./routers/products");
const transactions = require("./routers/transactions");

// Protect /products route with authentication middleware
app.use("/products", authenticateToken, product);
app.use("/transactions", authenticateToken, transactions);

app.listen(PORT, () => {
	console.log(`Server running on http://localhost:${PORT}`);
});
