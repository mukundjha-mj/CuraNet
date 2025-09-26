"use client";
import Link from "next/link";
import { motion } from "framer-motion";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

export default function Home() {
  return (
    <div className="py-8">
      <section className="text-center py-12">
        <motion.h1
          className="text-4xl md:text-5xl font-semibold tracking-tight"
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4 }}
        >
          CuraNet — Lifetime health records under your control.
        </motion.h1>
        <p className="mt-4 text-muted-foreground max-w-2xl mx-auto">
          Clear consent controls. Offline-friendly. Trusted by clinics. Your data, your decisions.
        </p>
        <div className="mt-8 flex items-center justify-center gap-4">
          <Link href="/auth/register?role=patient" className="rounded-md bg-primary text-primary-foreground px-5 py-2.5 font-medium">
            Sign up (Patient)
          </Link>
          <Link href="/auth/register?role=provider" className="rounded-md border px-5 py-2.5 font-medium">
            Sign up (Provider)
          </Link>
        </div>
      </section>

      <section className="grid gap-6 sm:grid-cols-2 lg:grid-cols-3 mt-6">
        {[
          { title: "Health ID", desc: "Single ID to link records across providers." },
          { title: "Consent controls", desc: "Grant, revoke, and audit who accessed your data." },
          { title: "Offline & local clinic", desc: "Drafts and uploads work without internet." },
        ].map((f) => (
          <Card key={f.title}>
            <CardHeader>
              <CardTitle>{f.title}</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-sm text-muted-foreground">{f.desc}</p>
            </CardContent>
          </Card>
        ))}
      </section>
    </div>
  );
}
