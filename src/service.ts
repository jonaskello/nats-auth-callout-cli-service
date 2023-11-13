import fs from "fs";
import { program } from "commander";
import * as Nats from "nats";
import * as Nkeys from "nkeys.js";
import * as Jwt from "nats-jwt";

program
  .option("-nats.url <nats-url>")
  .option("-nats.user <nats-user>")
  .option("-nats.pass <nats-pass>")
  .option("-issuer.seed <issuer-seed>")
  .option("-xkey.seed <xkey-seed>")
  .option("-users <users-json>")
  .action((opts) => {
    run(opts);
  });

program.parse(process.argv);

type Opts = {
  "Nats.url": string;
  "Nats.user": string;
  "Nats.pass": string;
  "Issuer.seed": string;
  "Xkey.seed": string;
  Users: string;
};

type AuthorizationRequestClaims = {
  user_nkey: string;
  server_id: { id: string };
  connect_opts: { user: string; pass: string };
};

type Permissions = {
  pub: { allow: Array<string>; deny: Array<string> };
  sub: { allow: Array<string>; deny: Array<string> };
  resp: { max: number; ttl: number };
};

type User = {
  pass: string;
  account: string;
  permissions?: Permissions;
};

async function run(opts: Opts) {
  const natsUrl = opts["Nats.url"];
  const natsUser = opts["Nats.user"];
  const natsPass = opts["Nats.pass"];
  const issuerSeed = opts["Issuer.seed"];
  const xkeySeed = opts["Xkey.seed"];
  const usersFile = opts["Users"];

  var enc = new TextEncoder();
  var dec = new TextDecoder();

  // Parse the issuer account signing key.
  const issuerKeyPair = Nkeys.fromSeed(enc.encode(issuerSeed));

  // Parse the xkey seed if present.
  let curveKeyPair: Nkeys.KeyPair | undefined;
  // if (xkeySeed.length > 0) {
  //   curveKeyPair = Nkeys.fromSeed(enc.encode(xkeySeed));
  // }

  // Load and decode the users file.
  const usersData = fs.readFileSync(usersFile, "utf-8");
  const users = JSON.parse(usersData);

  // Open the NATS connection passing the auth account creds file.
  const nc = await Nats.connect({ servers: natsUrl, user: natsUser, pass: natsPass });

  // Start subscription
  const sub = nc.subscribe("$SYS.REQ.USER.AUTH");
  console.log(`listening for ${sub.getSubject()} requests...`);
  for await (const msg of sub) {
    await msgHandler(msg, curveKeyPair, enc, dec, users, issuerKeyPair);
  }
}

async function msgHandler(
  req: Nats.Msg,
  curveKeyPair: Nkeys.KeyPair | undefined,
  enc: TextEncoder,
  dec: TextDecoder,
  users: Record<string, User>,
  issuerKeyPair: Nkeys.KeyPair
) {
  // Helper function to construct an authorization response.
  const respondMsg = async (req: Nats.Msg, userNkey: string, serverId: string, userJwt: string, errMsg: string) => {
    let token: string;
    try {
      token = await Jwt.encodeAuthorizationResponse(userNkey, serverId, issuerKeyPair, { jwt: userJwt, error: errMsg }, {});
    } catch (err) {
      console.log("error encoding response JWT: %s", err);
      req.respond(undefined);
      return;
    }

    let data = enc.encode(token);

    // // Check if encryption is required.
    // const xkey = req.headers?.get("Nats-Server-Xkey");
    // if (xkey && xkey.length > 0 && curveKeyPair) {
    //   try {
    //     //  data = curveKeyPair.Seal(data, xkey);
    //     data = new Uint8Array();
    //   } catch (err) {
    //     console.log("error encrypting response JWT: %s", err);
    //     req.respond(undefined);
    //     return;
    //   }
    // }

    req.respond(data);
  };

  // Check for Xkey header and decrypt
  let token: Uint8Array;
  // const xkey = req.headers?.get("Nats-Server-Xkey");
  // if (xkey && xkey.length > 0) {
  //   if (!curveKeyPair) {
  //     return respondMsg(req, "", "", "", "xkey not supported");
  //   }
  //   // Decrypt the message.
  //   try {
  //     // TODO: No open function to call...
  //     // const token = curveKeyPair.open(req.data, xkey);
  //     token = new Uint8Array();
  //   } catch (e) {
  //     return respondMsg(req, "", "", "", "error decrypting message");
  //   }
  // } else {
  token = req.data;
  // }

  // Decode the authorization request claims.
  let rc: AuthorizationRequestClaims;
  try {
    rc = Jwt.decode<AuthorizationRequestClaims>(dec.decode(token)).nats as AuthorizationRequestClaims;
  } catch (e) {
    return respondMsg(req, "", "", "", (e as Error).message);
  }

  // Used for creating the auth response.
  const userNkey = rc.user_nkey;
  const serverId = rc.server_id.id;

  // Check if the user exists.
  const userProfile = users[rc.connect_opts.user];
  if (!userProfile) {
    return respondMsg(req, userNkey, serverId, "", "user not found");
  }

  // Check if the credential is valid.
  if (userProfile.pass != rc.connect_opts.pass) {
    return respondMsg(req, userNkey, serverId, "", "invalid credentials");
  }

  // Prepare a user JWT.
  // Sign it with the issuer key since this is non-operator mode.
  let ejwt: string;
  try {
    ejwt = await Jwt.encodeUser(
      rc.connect_opts.user,
      rc.user_nkey,
      issuerKeyPair,
      // Set the associated permissions if present.
      userProfile.permissions,
      {
        // Audience contains the account in non-operator mode.
        aud: userProfile.account,
      }
    );
  } catch (e) {
    return respondMsg(req, userNkey, serverId, "", "error signing user JWT");
  }

  return respondMsg(req, userNkey, serverId, ejwt, "");
}
