import { AdminForms } from "@/ui/admin.tsx";

// What an admin of a workspace does: custom roles, letting the vendor's staff in, viewing the app as someone, the
// email intake's keys. Anyone else may open the page; the database refuses them, and says why.
export default function Page() {
  return (
    <>
      <h1>Admin</h1>
      <AdminForms />
    </>
  );
}
