import axios from "axios";
import {Command, OptionValues} from "commander";
import * as fs from "fs";

const URL_PREFIX = "https://us-central1-openid3-bbd1b.cloudfunctions.net/";
const LOCAL_URL_PREFIX = "http://127.0.0.1:5001/openid3-bbd1b/us-central1/submitZkProof";

export async function callFirebaseFunction(
    data: unknown,
    token?: string
) {
  const config = token ? {headers: {"Authorization": "Bearer " + token}} : {};
  const url = process.env.NODE_ENV === "production" ? URL_PREFIX : LOCAL_URL_PREFIX;
  return await axios.post(url, data, config);
}

export async function submitZkpProof(options: OptionValues) {
  const proof = fs.readFileSync(options.proof, "utf-8");
  const result = await callFirebaseFunction(
      {
        uid: options.uid,
        idToken: options.idtoken,
        success: true,
        proof: JSON.parse(proof),
      },
      "randomsecret"
  );
  if (!result.data || !result.data.success) {
    throw new Error("failed to submit zkp proof");
  }
}

const program = new Command();
program.option("-u, --uid <char>")
    .option("-i, --idtoken <char>")
    .option("-p, --proof <char>", "the file path of the proof");

program.parse();
const options = program.opts();
submitZkpProof(options);
