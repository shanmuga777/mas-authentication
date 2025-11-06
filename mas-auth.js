// npm install express axios tough-cookie axios-cookiejar-support
import express from "express";
import axios from "axios";
import { CookieJar } from "tough-cookie";
import { wrapper } from "axios-cookiejar-support";

// Disable SSL verification globally (same as Postman "Disable SSL Verification")
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

const app = express();
app.use(express.json());

app.post("/login", async (req, res) => {
  const {
    username,
    password,
    authurl,
    manageurl,
    idpendpoint,
    params,
    ldapDomain = "default-ldap", // optional LDAP domain
  } = req.body;

  if (!username || !password || !authurl || !manageurl || !idpendpoint) {
    return res.status(400).json({ error: "Missing parameters" });
  }

  const jar = new CookieJar();
  const client = wrapper(
    axios.create({
      jar,
      withCredentials: true,
      maxRedirects: 10,
      validateStatus: () => true, // allow redirects and all HTTP codes
    })
  );

  try {
    // Step 1: Load login page
    let loginPageUrl = `${authurl}${idpendpoint}`;
    if (params && typeof params === "object") {
      const queryString = new URLSearchParams(params).toString();
      loginPageUrl += `?${queryString}`;
    }
    await client.get(loginPageUrl);

    // Step 2: Format LDAP username and submit credentials
    const ldapUsername = `ldap=${ldapDomain}:username=${username}`;
    const loginUrl = `${authurl}/js/j_security_check?j_username=${encodeURIComponent(
      ldapUsername
    )}&j_password=${encodeURIComponent(password)}`;
    await client.post(loginUrl, null);

    // Step 3: Extract x-access-token cookie
    const cookies = await jar.getCookies(authurl);
    const accessToken = cookies.find(
      (c) => c.key.toLowerCase() === "x-access-token"
    );

    if (!accessToken) {
      return res.status(401).json({ message: "Wrong username or password" });
    }

    // Step 4: Use token to call Maximo API
    const tokenUrl = `${manageurl}/maximo/oslc/script/teamauthenticate`;
    const apiResponse = await client.get(tokenUrl, {
      headers: { "x-access-token": accessToken.value },
    });

    // Step 5: Return final response
    return res.status(200).json({
      message: "Login successful",
      apiResponse: apiResponse.data,
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.listen(5005, () => {
  console.log("Server running on port 5005");
});
