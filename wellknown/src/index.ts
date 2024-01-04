import cors from "cors";
import express, { Application } from "express";
import { getPubkeyFromName, getPubkeyFromAddress, stripHex } from "./ns";
import { HexString, HexlinkError } from "./types";

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
    const pubkey = await getPubkeyFromName(name);
    if (pubkey) {
      const normalized = stripHex(pubkey);
      return res.status(200).json({
        names: { [name]: normalized },
        relays: {
          [normalized]: [process.env.DEFAULT_RELAY],
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

app.get("/api/nostrkey", async (req, res) => {
  try {
    let pubkey: HexString | undefined;
    if (req.query.name) {
      pubkey = await getPubkeyFromName(req.query.name as string);
    } else if (req.query.address) {
      pubkey = await getPubkeyFromAddress(req.query.address as string);
    } else {
      throw new HexlinkError(400, "name or address is required");
    }
    if (pubkey) {
      const normalized = stripHex(pubkey);
      return res.status(200).json({ pubkey: normalized });
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

app.get("/api/passkey", async (req, res) => {
});

app.get("*", function (_req, res) {
  return res.status(404).send("Path Not Supported");
});

app.listen(port, "0.0.0.0", () => {
  console.log(`Server is Fire at http://localhost:${port}`);
});
