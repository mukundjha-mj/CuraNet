import Protected from "@/components/protected";

export default function PatientDashboard() {
  return (
    <Protected>
      <h1 className="text-2xl font-semibold">Patient Dashboard</h1>
      <p className="text-muted-foreground mt-2">Timeline, emergency card, uploads soon.</p>
    </Protected>
  );
}
