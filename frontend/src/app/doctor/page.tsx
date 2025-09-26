import Protected from "@/components/protected";

export default function DoctorDashboard() {
  return (
    <Protected>
      <h1 className="text-2xl font-semibold">Doctor Dashboard</h1>
      <p className="text-muted-foreground mt-2">Patient search, encounter drafts soon.</p>
    </Protected>
  );
}
