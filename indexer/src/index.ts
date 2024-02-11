import cors from "cors";
import express, { Application } from "express";
import {
  getOperatorsFromAddress,
  getMetadataFromAddress,
  getPasskeyFromAddress,
} from "./ns";
import { ServerError, HexString } from "./types";
import { ratelimit } from "./ratelimiter";

const app: Application = express();
const port = Number(process.env.PORT) || 8000;

const ip = (req: express.Request) => {
  return req.headers['x-forwarded-for'] || req.socket.remoteAddress 
}

app.get("/api/account/metadata", cors(), async (req, res) => {
  try {
    if (await ratelimit(ip(req) as string)) {
      throw new ServerError(429, "Rate limit exceeded");
    }
    const metadata = await getMetadataFromAddress(req.query.address as string);
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
    if (await ratelimit(ip(req) as string)) {
      throw new ServerError(429, "Rate limit exceeded");
    }
    const passkey = await getPasskeyFromAddress(req.query.address as string);
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
    if (await ratelimit(ip(req) as string)) {
      throw new ServerError(429, "Rate limit exceeded");
    }
    const operators = await getOperatorsFromAddress(req.query.address as HexString);
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
