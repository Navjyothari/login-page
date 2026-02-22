const express = require('express');
const cors = require('cors');

const app = express();

app.use(express.static('public'));
app.use(cors());

const port = 3000;

app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});