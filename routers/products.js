const express = require("express");
const products = express.Router();
const { fetchProduct, addProduct } = require("../controllers/products");

//Swagger get Product
/**
 * @swagger
 * /products:
 *   get:
 *     summary: product fetcher
 *     tags: [products]
 *     responses:
 *       200:
 *         description: product fetched
 *       403:
 *         description: failed to fetch product
 */

products.route("/").get(async (req, res) => {
  res.send(await fetchProduct());
});

products.route("/").post(async (req, res) => {
  const { name, price, stock } = req.body;
  const data = {
    name,
    price,
    stock,
  };
  res.send(await addProduct(data));
}); 

module.exports = products;
