import { openDB, IDBPDatabase } from "idb";

type QueuedOp = {
  id: string; // uuid
  path: string;
  method: "POST" | "PUT" | "PATCH" | "DELETE";
  body: unknown;
  createdAt: number;
};

type Draft = {
  id: string;
  type: string; // e.g., "encounter" | "note"
  payload: unknown;
  updatedAt: number;
};

let dbPromise: Promise<IDBPDatabase> | null = null;

function getDb() {
  if (!dbPromise) {
    dbPromise = openDB("curanet", 1, {
      upgrade(db) {
        db.createObjectStore("queue", { keyPath: "id" });
        db.createObjectStore("drafts", { keyPath: "id" });
      },
    });
  }
  return dbPromise;
}

export async function addQueuedOp(op: QueuedOp) {
  const db = await getDb();
  await db.put("queue", op);
}

export async function getQueuedOps(): Promise<QueuedOp[]> {
  const db = await getDb();
  return (await db.getAll("queue")) as QueuedOp[];
}

export async function removeQueuedOp(id: string) {
  const db = await getDb();
  await db.delete("queue", id);
}

export async function upsertDraft(draft: Draft) {
  const db = await getDb();
  await db.put("drafts", draft);
}

export async function getDraft(id: string): Promise<Draft | undefined> {
  const db = await getDb();
  return (await db.get("drafts", id)) as Draft | undefined;
}

export async function listDrafts(): Promise<Draft[]> {
  const db = await getDb();
  return (await db.getAll("drafts")) as Draft[];
}

export type { QueuedOp, Draft };
