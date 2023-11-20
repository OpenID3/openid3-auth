import axios from "axios";
import {Command, OptionValues} from "commander";
import * as fs from "fs";

export async function callFirebaseFunction(
    func: string,
    data: unknown,
    token?: string
) {
  const urlPrefix = `https://us-central1-${process.env.VITE_FIREBASE_PROJECT_ID}.cloudfunctions.net/`;
  const config = token ? {headers: {"Authorization": "Bearer " + token}} : {};
  return await axios.post(`${urlPrefix}${func}`, data, config);
}

export async function submitZkpProof(options: OptionValues) {
  const proof = fs.readFileSync(options.proof, "utf-8");
  const result = await callFirebaseFunction(
      "submitZkProof",
      {
        uid: options.uid,
        idToken: options.idtoken,
        success: true,
        proof: JSON.parse(proof),
      }
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
