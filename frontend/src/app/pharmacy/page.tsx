import Protected from "@/components/protected";

export default function PharmacyDashboard() {
  return (
    <Protected>
      <h1 className="text-2xl font-semibold">Pharmacy Dashboard</h1>
      <p className="text-muted-foreground mt-2">Prescription queue and dispense flow soon.</p>
    </Protected>
  );
}
