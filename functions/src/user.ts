import cors from "cors";
import * as functions from "firebase-functions";

import {
  HexlinkError,
  handleError,
} from "./utils";
import {checkNameRateLimit} from "./ratelimiter";
import {resolveName} from "./db/ns";
import {getUser} from "./db/user";

const secrets = functions.config().doppler || {};

/**
 * req.body: {
 *   uid: string,
 * }
 *
 * res: {
 *   registered: boolean,
 *   address?: string, // only valid if registered is true
 */

export const getAddressByUid = functions.https.onRequest((req, res) => {
  return cors({origin: true, credentials: true})(req, res, async () => {
    try {
      if (secrets.ENV !== "dev" && (await checkNameRateLimit(req.ip || ""))) {
        throw new HexlinkError(429, "Too many requests");
      }
      const address = await resolveName(req.body.uid);
      if (!address) {
        res.status(200).json({registered: false});
      } else {
        res.status(200).json({registered: true, address});
      }
    } catch (err: unknown) {
      handleError(res, err);
    }
  });
});

/**
 * req.body: {
 *   uid: string,
 * }
 *
 * res: {
 *   registered: boolean,
 *   user?: { // only valid if registered is true
 *     address: string,
 *     factory: string,
 *     operator: string,
 *     metadata: string,
 *     passkey: Passkey,
 *   }
 */
export const getUserByUid = functions.https.onRequest((req, res) => {
  return cors({origin: true, credentials: true})(req, res, async () => {
    try {
      if (secrets.ENV !== "dev" && (await checkNameRateLimit(req.ip || ""))) {
        throw new HexlinkError(429, "Too many requests");
      }
      const address = await resolveName(req.body.uid);
      if (!address) {
        res.status(200).json({registered: false});
      } else {
        const user = await getUser(address);
        if (user) {
          res.status(200).json({
            registered: true,
            user: {
              address,
              factory: user.factory,
              passkey: user.passkey,
              operator: user.operator,
              metadata: user.metadata,
            },
          });
        } else {
          throw new HexlinkError(500, "user data lost");
        }
      }
    } catch (err: unknown) {
      handleError(res, err);
    }
  });
});

/**
 * req.body: {
 *   address: string,
 * }
 *
 * res: {
 *   registered: boolean,
 *   user?: { // only valid if registered is true
 *     address: string,
 *     factory: string,
 *     operator: string,
 *     metadata: string,
 *     passkey: Passkey,
 *   }
 */
export const getUserByAddress = functions.https.onRequest((req, res) => {
  return cors({origin: true, credentials: true})(req, res, async () => {
    try {
      if (secrets.ENV !== "dev" && (await checkNameRateLimit(req.ip || ""))) {
        throw new HexlinkError(429, "Too many requests");
      }
      const user = await getUser(req.body.address);
      if (user) {
        res.status(200).json({
          registered: true,
          user: {
            address: req.body.address,
            factory: user.factory,
            passkey: user.passkey,
            operator: user.operator,
            metadata: user.metadata,
          },
        });
      } else {
        throw new HexlinkError(404, "user not found");
      }
    } catch (err: unknown) {
      handleError(res, err);
    }
  });
});
