export {
  errorCode,
  ensurePrivateDirectory,
  validatePrivateDirectory,
} from "./transaction/atomic-file.js";
export { sha256 } from "../utils/hash.js";
export {
  applyFileTransaction,
  writePrivateFileAtomically,
  type AcceptInstalledUpdate,
} from "./transaction/apply.js";
export { withPrivateFileLock } from "./transaction/private-lock.js";
export {
  isPrivateFileMode,
  readPrivateFileSnapshot,
  readSnapshot,
  sameFileSnapshot,
  type FileSnapshot,
  type PlannedDelete,
  type PlannedFileChange,
  type PlannedWrite,
} from "./transaction/snapshots.js";
