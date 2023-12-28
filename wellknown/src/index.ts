import cors from "cors";
import express, { Application } from "express";
import { getPubkey } from "./ns";
import { HexlinkError } from "./types";

const app: Application = express();
const port = Number(process.env.PORT) || 8000;
app.use(cors());

app.get("/.well-known/nostr.json", async (req, res) => {
  if (!req.query.name || typeof req.query.name !== "string") {
    res.status(400).json({ message: "name is required" });
    return;
  }

  const name = req.query.name;
  try {
    const pubkey = await getPubkey(name);
    if (pubkey) {
      return res.status(200).json({
        names: { [name]: pubkey },
        relays: {
          [pubkey]: ["https://relay.hexlink.io"]
        },
      });
    } else {
      return res.status(404).send("Not found");
    }
  } catch (err: unknown) {
    if (err instanceof HexlinkError) {
      return res.status(err.code).json({ message: err.message });
    } else {
      console.log("Error: ", err);
      return res.status(500).json({ message: "internal server error" });
    }
  }
});

app.get('*', function(_req, res) {
  return res.status(404).send('Not Found');
});

app.listen(port, "0.0.0.0", () => {
  console.log(`Server is Fire at http://localhost:${port}`);
});
