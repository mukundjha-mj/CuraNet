// Ambient declarations to satisfy TypeScript in absence of local type definitions

declare namespace NodeJS {
  interface ProcessEnv {
    JWT_SECRET?: string;
  }
}

declare module '../models/*' {
  const anyModel: any;
  export default anyModel;
}

declare module '../../ride/service/*' {
  export function subscribeToQueue(queue: string, cb: (msg: any) => void): void;
}
