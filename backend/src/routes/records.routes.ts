import express from 'express';
import { authenticateToken } from '../middlewares/authMiddleware';
import ctrl from '../controllers/records.controller';

const router = express.Router();

// Encounters
router.post('/encounters/create', authenticateToken, ctrl.createEncounter);
router.post('/encounters/get/:id', authenticateToken, ctrl.getEncounter);
router.post('/encounters/list', authenticateToken, ctrl.listEncounters);

// Observations
router.post('/observations/create', authenticateToken, ctrl.createObservation);
router.post('/observations/get/:id', authenticateToken, ctrl.getObservation);
router.post('/observations/list', authenticateToken, ctrl.listObservations);

export default router;
