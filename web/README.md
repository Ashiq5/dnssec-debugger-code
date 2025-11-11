1. Architecture
User -> Nginx -> FastAPI -> PostGreSQL
                 ↓          ↑
                 Redis   <- Worker -> ZRep & DFixer
2. All containerized
3. To deploy, just run the following command:
   a. `docker-compose down` (not required first time)
   b. `docker-compose up -d --build --scale worker=4`
4. FastAPI pushes job to Redis, saves requests in a PSQL db. Worker containers takes job from Redis queue, 
calls ZRep & DFixer, and then updates PSQL db.
