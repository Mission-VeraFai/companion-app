"use server";

// server action to allow configuration of LLM from .env.local

import dotenv from "dotenv";
import * as path from "path";
import * as fs from "fs/promises";


// Allowlisted base directory and filename — never derived from user input.
const COMPANIONS_BASE_DIR = path.resolve(process.cwd(), "companions");
const COMPANIONS_FILENAME = "companions.json";

export async function getCompanions() {
  // Resolve to an absolute path and validate it stays within the allowed directory.
  const resolvedPath = path.resolve(COMPANIONS_BASE_DIR, COMPANIONS_FILENAME);
  if (!resolvedPath.startsWith(COMPANIONS_BASE_DIR + path.sep) &&
      resolvedPath !== path.join(COMPANIONS_BASE_DIR, COMPANIONS_FILENAME)) {
    throw new Error("Invalid companions file path — potential path traversal detected.");
  }

  const data = await fs.readFile(resolvedPath, { encoding: "utf-8" });
  // run a parse here to force a server side error if the JSON is improperly formatted
  // It's much more difficult to debug client side
  var js = JSON.parse(data);
  // Return only the minimised subset of fields required by the client
  const minimised = (Array.isArray(js) ? js : [js]).map(
    ({ id, name, description }: { id?: string; name?: string; description?: string }) => ({
      ...(id !== undefined && { id }),
      ...(name !== undefined && { name }),
      ...(description !== undefined && { description }),
    })
  );
  return JSON.stringify(minimised);
}