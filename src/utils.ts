import * as functions from "firebase-functions";

export const epoch = () => {
  return Math.floor(new Date().getTime() / 1000);
};

export class HexlinkError extends Error {
  code: number;

  constructor(code: number, message: string) {
    super(message);
    this.code = code;
  }
}

export const handleError = function(
    res: functions.Response,
    err: unknown
) {
  if (err instanceof HexlinkError) {
    res.status(err.code).json({message: err.message});
  }
  console.log("Error: ", err);
  res.status(500).json({message: "internal server error"});
};
