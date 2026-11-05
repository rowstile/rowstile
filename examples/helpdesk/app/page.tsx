import { SignIn } from "@/ui/sign-in.tsx";

// the demo's people (db/seed.sql): pick one, and see the desk as they do
const people = [
  ["ann@acme.test", "Ann, Acme's admin"],
  ["lea@acme.test", "Lea, who leads Support (Billing and Hardware are inside it)"],
  ["al@acme.test", "Al, in Billing"],
  ["oz@acme.test", "Oz, in Hardware"],
  ["peter@initech.test", "Peter, a customer at Initech (whose people share their tickets)"],
  ["cy@mail.test", "Cy, a customer"],
  ["bob@globex.test", "Bob, Globex's admin: another workspace"],
  ["sam@vendor.test", "Sam, the vendor's support staff"],
];

export default function Page() {
  return (
    <>
      <h1>Sign in</h1>
      <p>Each person sees the desk as the database lets them: the app has no permission checks of its own.</p>
      <SignIn people={people} />
    </>
  );
}
