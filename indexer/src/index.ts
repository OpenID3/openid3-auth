import cors from "cors";
import express, { Application } from "express";
import {
  getOperatorsFromName,
  getOperatorsFromAddress,
  getMetadataFromName,
  getMetadataFromAddress,
  stripHex,
  getPasskeyFromAddress,
  getPasskeyFromName,
  getNostrInfoFromName,
} from "./ns";
import { HexString, HexlinkError, Passkey } from "./types";
import { ServerError } from "./utils";

const app: Application = express();
const port = Number(process.env.PORT) || 8000;

app.get("/.well-known/nostr.json", cors(), async (req, res) => {
  if (!req.query.name || typeof req.query.name !== "string") {
    res.status(400).json({ message: "name is required" });
    return;
  }

  const name = req.query.name;
  try {
    const nostr = await getNostrInfoFromName(name);
    if (nostr) {
      const normalized = stripHex(nostr.nostrPubkey);
      return res.status(200).json({
        names: { [name]: normalized },
        relays: {
          [normalized]: nostr.relays,
        },
      });
    } else {
      return res.status(404).send("Not found");
    }
  } catch (err: unknown) {
    handleError(res, err);
  }
});

app.get("/api/account/metadata", cors(), async (req, res) => {
  try {
    let metadata: string | undefined;
    if (req.query.name) {
      metadata = await getMetadataFromName(req.query.name as string);
    } else if (req.query.address) {
      metadata = await getMetadataFromAddress(req.query.address as string);
    } else {
      throw new HexlinkError(400, "name or address is required");
    }
    if (metadata) {
      return res.status(200).json({ metadata });
    } else {
      return res.status(404).send("Not found");
    }
  } catch (err: unknown) {
    handleError(res, err);
  }
});

app.get("/api/account/passkey", cors(), async (req, res) => {
  try {
    let passkey: Passkey | undefined;
    if (req.query.name) {
      passkey = await getPasskeyFromName(req.query.name as string);
    } else if (req.query.address) {
      passkey = await getPasskeyFromAddress(req.query.address as string);
    } else {
      throw new HexlinkError(400, "name or address is required");
    }
    if (passkey) {
      return res.status(200).json({ passkey });
    } else {
      return res.status(404).send("Not found");
    }
  } catch (err: unknown) {
    handleError(res, err);
  }
});

app.get("/api/account/operators", cors(), async (req, res) => {
  try {
    let operators: HexString | undefined;
    if (req.query.name) {
      operators = await getOperatorsFromName(req.query.name as string);
    } else if (req.query.address) {
      operators = await getOperatorsFromAddress(req.query.address as HexString);
    } else {
      throw new HexlinkError(400, "name or address is required");
    }
    if (operators) {
      return res.status(200).json({ operators });
    } else {
      return res.status(404).send("Not found");
    }
  } catch (err: unknown) {
    handleError(res, err);
  }
});

app.get("*", function (_req, res) {
  return res.status(404).send("Path Not Supported");
});

app.listen(port, "0.0.0.0", () => {
  console.log(`Server is Fire at http://localhost:${port}`);
});

const handleError = (res: express.Response, err: unknown) => {
  if (err instanceof ServerError) {
    res.status(err.code).json({ message: err.message });
  } else {
    console.log("Error: ", err);
    res.status(500).json({ message: "internal server error" });
  }
};
