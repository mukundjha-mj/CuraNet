import Protected from "@/components/protected";

export default function AdminConsole() {
  return (
    <Protected>
      <h1 className="text-2xl font-semibold">Admin Console</h1>
      <p className="text-muted-foreground mt-2">Provider approvals and metrics soon.</p>
    </Protected>
  );
}
