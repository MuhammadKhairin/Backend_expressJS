const express = require("express");
const transactions = express.Router();
const { randomOrderNumber } = require("../helpers/utils");
const { addTransaction } = require("../controllers/transactions");

transactions.route(`/`).post(async (req, res) => {
  const { total_price, products } = req.body;
  if (products.length === 0) {
    return res.status(400).json({ error: "Shopping cart is empty. Unable to proceed with transaction." });
  }
  const order = {
    no_order: randomOrderNumber(),
    total_price,
  };
  res.send(await addTransaction(order, products))
});


module.exports = transactions;