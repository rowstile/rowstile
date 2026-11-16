// An identity provider's users and groups (SCIM: Okta, Microsoft Entra ID): the database answers each request
import { scimRoutes } from "@rowstile/next";
import { db } from "@/db";

export const { GET, POST, PUT, PATCH, DELETE } = scimRoutes({ calls: db.$authz });
