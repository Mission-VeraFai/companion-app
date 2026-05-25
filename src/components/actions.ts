"use server";

// server action to allow configuration of LLM from .env.local

import dotenv from "dotenv";
import { parse } from "path";


export async function getCompanions() {
  const COMPFILE = "./companions/companions.json";
  var companions = [];
  // console.log("Loading companion descriptions from "+COMPFILE);
  var fs = require('fs');
  const data = fs.readFileSync(COMPFILE);
  // run a parse here to force a server side error if the JSON is improperly formatted
  // It's much more difficult to debug client side
  var js = JSON.parse(String(data));
  // Apply field minimisation: only expose safe, non-sensitive fields to the client
  const allowedFields = ["id", "name", "description"];
  const minimised = (Array.isArray(js) ? js : [js]).map((companion: Record<string, unknown>) =>
    Object.fromEntries(
      Object.entries(companion).filter(([key]) => allowedFields.includes(key))
    )
  );
  console.log(`Loaded ${minimised.length} companion(s) from ${COMPFILE}`);
  return JSON.stringify(minimised);
}