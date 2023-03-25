const appServer = require("./appServer");
const authServer = require("./authServer");
const request = require("supertest");
const bcrypt = require("bcrypt");
const userModel = require("./userModel.js");
const jwt = require("jsonwebtoken");
const { test } = require("media-typer");
const { response } = require("./appServer");

describe("/register", () => {
  it('should create a new user in the database with the correct hashed password', async () => {
    const user = {
      name: 'Ash',
      email: 'example@example.com',
      password: 'password123'
    };
    const response = await request(authServer)
      .post("/register")
      .send(newUser)
      .expect(200);

    expect(response.status).toBe(200);
    expect(response.body.username).toBe(newUser.username);
    expect(response.body.email).toBe(newUser.email);
    expect(response.body.password).not.toBe(newUser.password);

    // Verify that the password is correctly hashed
    const createdUser = await userModel.findOne({ username: newUser.username });
    const isPasswordCorrect = await bcrypt.compare(
      newUser.password,
      createdUser.password
    );
    expect(isPasswordCorrect).toBe(true);
  });
});


describe("/login", () => {
  it("returns JWT access token and refresh token for valid credentials", async () => {
    const credentials = {
      username: "admin",
      password: "admin",
    };

    const response = await request(app)
      .post('/login')
      .send(credentials);

    expect(response.statusCode).toBe(200);
    expect(response.header["auth-token-access"]).toBeDefined();
    expect(response.header["auth-token-refresh"]).toBeDefined();
  });

  it("should throw PokemonAuthError for invalid credentials", async () => {
    const credentials = {
       email: 'invalid@example.com',
      password: 'invalid',
    };

    const response = await request(authServer).post("/login").send(credentials);

    expect(response.statusCode).toBe(401);
  });
});

describe("/requestNewAccessToken", () => {
  let refreshToken;
  beforeEach(async () => {
    const credentials = {
      email: 'admin@example.com',
      password: 'admin',
    };

    const response = await request(app)
      .post('/login')
      .send(credentials);

    refreshToken = response.header["auth-token-refresh"];
  });

  it("should return a new JWT access token for a valid refresh token", async () => {
    const res = await request(authServer)
      .post("/requestNewAccessToken")
      .set("Authorization", `Bearer ${refreshToken}`);

    expect(res.status).toBe(200);
    expect(res.body.accessToken).toBeDefined();
  });

  it("should throw a PokemonAuthError for an invalid or missing refresh token", async () => {
    const res = await request(authServer).post("/requestNewAccessToken");
    expect(res.status).toBe(401);
    //expect(res.body.message).toBe("No Token: Please provide a token");

    const invalidToken = "invalid_token";
    const res2 = await request(authServer)
      .post("/requestNewAccessToken")
      .set("auth-token-refresh", invalidToken);
    expect(res2.status).toBe(401);
    //expect(res2.body.message).toBe("Invalid token: please provide a valid token")
  });
});

describe("Authentication", () => {
  let refreshToken;

  beforeEach(async () => {
    const credentials = {
      email: 'admin@example.com',
      password: 'admin',
    };

    const response = await request(app)
      .post('/login')
      .send(credentials);

    refreshToken = response.header["auth-token-refresh"];
  });

  afterAll(async () => {
    await request(authServer).get("/logout").query({ appid: "some-app-id" });
  });

  it("should login and add refresh token to refreshTokens array", async () => {
    const res = await request(authServer).post("/login").send({
      username: "admin",
      password: "admin",
    });

    expect(res.statusCode).toEqual(200);
    expect(res.headers["auth-token-access"]).toBeTruthy();
    refreshToken = res.headers["auth-token-refresh"];
    expect(refreshToken).toBeTruthy();
    expect(authServer.refreshToken).toContain(refreshToken);
  });

  it("should not request new access token without refresh token", async () => {
    const res = await request(authServer).post("/requestNewAccessToken");

    expect(res.statusCode).toEqual(401);
  });

  it("should not request new access token with invalid refresh token", async () => {
    const res = await request(authServer)
      .post("/requestNewAccessToken")
      .set("auth-token-refresh", "invalid-token");

    expect(res.statusCode).toEqual(401);
  });

  it("should request new access token with valid refresh token", async () => {
    const res = await request(authServer)
      .post("/requestNewAccessToken")
      .set("auth-token-refresh", refreshToken);

    expect(res.statusCode).toEqual(200);
    expect(res.headers["auth-token-access"]).toBeTruthy();
    console.log("token: " + res.headers["auth-token-access"]);
  });

  it("should logout and remove the refresh token from refreshTokens array", async () => {
    const res = await request(authServer)
      .get("/logout")
      .query({ appid: "some-app-id" });

    expect(res.statusCode).toEqual(200);
    expect(authServer.refreshTokens).not.toContain(refreshToken);
  });
});

describe("/login", () => {
  it("should return a valid access token that contains the correct user data", async () => {
    const credentials = {
      username: "admin",
      password: "admin",
    };

    const response = await request(authServer)
      .post("/login")
      .send(credentials)
      .expect(200);

    const accessToken = response.headers["auth-token-access"];

    const decoded = jwt.verify(
      accessToken,
      process.env.ACCESS_TOKEN_SECRET
    );

    expect(decoded.user.username).toBe(credentials.username);
    expect(decoded.user.role).toBe("admin");
  });
});


describe("a user can successfully register, login and make a request with a JWT access token", () => {
  let accessToken = "";
  const newUser = {
    username: "Devon",
    password: "test123",
    email: "Devon@example.com",
  };

  it("Should register a new user", async () => {
    const res = await request(authServer).post("/register").send(newUser);
    expect(res.statusCode).toEqual(200);
  });

  it("should login with registered user", async () => {
    const res = await request(authServer).post("/login").send(newUser);
    expect(res.statusCode).toEqual(200);
    accessToken = res.headers["auth-token-access"];
  });

  it("should make a request with JWT access token", async () => {
    const res = await request(authServer)
      .get("/protected-endpoint")
      .set("Authorization", `Bearer ${accessToken}`);
    expect(res.statusCode).toEqual(200);
  });
});

describe("Protected endpoints", () => {
  it("returns a 401 when accessing protected endpoint without token", async () => {
    const res = await request(authServer).get("/protected-endpoint");

    expect(res.statusCode).toEqual(401);
  });
});

describe("Expired access token", () => {
  let accessToken;

  beforeAll(async () => {
    const admin = {
      username: "admin",
      password: "admin",
    };
    const res = await request(authServer).post("/login").send(admin);

    accessToken = res.headers["auth-token-access"];
  });

  it("should not be able to access a protected endpoint using an expired token", async () => {
    await new Promise((resolve) => setTimeout(resolve, 4000));

    const res = await request(authServer)
      .get("/protected-endpoint")
      .set("Authorization", `Bearer ${accessToken}`);
    expect(res.statusCode).toBe(401);
  });
});

describe("Protected endpoints PokemonAuthError", () => {
  it("should return a 401 error when accessing a protected endpoint with an invalid JWT access token", async () => {
    const res = await request(authServer)
      .get("/protected-endpoint")
      .set("Authorization", "Bearer invalid-token");

    expect(res.status).toBe(401);
    expect(response.body.error).toBe("PokemonAuthError");
  });
});

describe("Admin-protected routes", () => {
  it("should return 401 for non-admin user", async () => {
    const normalUser = {
      username: "username1",
      password: "password1",
      email: "user1@test.com",
      role: "user",
    };

    await request(authServer).post("/register").send(normalUser);

    const loginRes = await request(authServer).post("/login").send({
      username: "username1",
      password: "password1",
    });
    const accessToken = loginRes.header["auth-token-access"];

    const response = await request(authServer)
      .get("/protected-endpoint-admin")
      .set("Authorization", `Bearer ${accessToken}`);

    expect(response.status).toBe(401);
  });
});

describe("Protected endpoint", () => {
  let accessToken;
  let refreshToken;

  beforeAll(async () => {
    // Login as a user and obtain access and refresh tokens
    const response = await request(authServer)
      .post("/login")
      .send({ username: "user", password: "password" });
    accessToken = response.header["auth-token-access"];
    refreshToken = response.header["auth-token-refresh"];
  });

  it("should allow access with valid access token", async () => {
    // Use access token to access the protected endpoint
    const response = await request(authServer)
      .get("/protected-endpoint")
      .set("Authorization", `Bearer ${accessToken}`);
    expect(response.statusCode).toBe(200);
  });

  it("should disallow access with invalid access token", async () => {
    // Logout the user
    const responseLogout = await request(authServer).get("/logout");
    expect(responseLogout.statusCode).toBe(200);

    // Use the same access token to access the protected endpoint again
    const responseProtected = await request(authServer)
      .get("/protected-endpoint")
      .set("Authorization", `Bearer ${accessToken}`);
    expect(responseProtected.statusCode).toBe(401);
  });
});
