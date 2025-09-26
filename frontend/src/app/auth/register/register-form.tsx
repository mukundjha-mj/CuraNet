"use client";
import { useForm } from "react-hook-form";
import { z } from "zod";
import { zodResolver } from "@hookform/resolvers/zod";
import { useState } from "react";
import { toast } from "sonner";
import { apiFetch } from "@/lib/api";
import { useSearchParams } from "next/navigation";

const schema = z.object({
  name: z.string().min(2),
  email: z.string().email(),
  phone: z.string().min(10),
  password: z.string().min(8),
  role: z.enum(["patient", "doctor", "pharmacy", "admin"]),
});

type FormValues = z.infer<typeof schema>;

export default function RegisterForm() {
  const params = useSearchParams();
  const hintedRole = (params.get("role") as FormValues["role"] | null) ?? "patient";
  const [loading, setLoading] = useState(false);
  const {
    register,
    handleSubmit,
    setValue,
    formState: { errors },
  } = useForm<FormValues>({ resolver: zodResolver(schema), defaultValues: { role: hintedRole } });

  async function onSubmit(values: FormValues) {
    setLoading(true);
    try {
      const resp = await apiFetch<any>("/api/auth/register", { method: "POST", body: values });
      const token = resp?.devVerificationToken as string | undefined;
      if (token) {
        const link = `${location.origin}/auth/verify?token=${encodeURIComponent(token)}`;
        toast.success("Dev: click to verify now", { action: { label: "Open", onClick: () => (window.location.href = link) } });
      } else {
        toast.success("Check your email to verify your account.");
      }
      window.location.href = "/auth/login";
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Registration failed";
      toast.error(msg);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="max-w-md mx-auto">
      <h1 className="text-2xl font-semibold">Create your account</h1>
      <form onSubmit={handleSubmit(onSubmit)} className="mt-6 space-y-4">
        <div>
          <label className="block text-sm font-medium">Name</label>
          <input className="mt-1 w-full rounded-md border px-3 py-2" {...register("name")} />
          {errors.name && <p className="text-sm text-destructive mt-1">{errors.name.message}</p>}
        </div>
        <div>
          <label className="block text-sm font-medium">Email</label>
          <input type="email" className="mt-1 w-full rounded-md border px-3 py-2" {...register("email")} />
          {errors.email && <p className="text-sm text-destructive mt-1">{errors.email.message}</p>}
        </div>
        <div>
          <label className="block text-sm font-medium">Phone</label>
          <input className="mt-1 w-full rounded-md border px-3 py-2" {...register("phone")} />
          {errors.phone && <p className="text-sm text-destructive mt-1">{errors.phone.message}</p>}
        </div>
        <div>
          <label className="block text-sm font-medium">Role</label>
          <select
            className="mt-1 w-full rounded-md border px-3 py-2"
            {...register("role")}
            onChange={(e) => setValue("role", e.target.value as FormValues["role"]) }
            defaultValue={hintedRole}
          >
            <option value="patient">Patient</option>
            <option value="doctor">Doctor</option>
            <option value="pharmacy">Pharmacy</option>
            <option value="admin">Admin</option>
          </select>
          {errors.role && <p className="text-sm text-destructive mt-1">{errors.role.message}</p>}
        </div>
        <div>
          <label className="block text-sm font-medium">Password</label>
          <input type="password" className="mt-1 w-full rounded-md border px-3 py-2" {...register("password")} />
          {errors.password && <p className="text-sm text-destructive mt-1">{errors.password.message}</p>}
        </div>
        <button disabled={loading} className="rounded-md bg-primary text-primary-foreground px-4 py-2">
          {loading ? "Creating…" : "Create account"}
        </button>
      </form>
    </div>
  );
}
