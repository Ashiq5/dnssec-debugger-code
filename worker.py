from rq import Worker, Queue
from redis import Redis

redis_conn = Redis(host="redis", port=6379)
q = Queue(connection=redis_conn, name="main_tasks")
print("Listening to incoming jobs")
worker = Worker([q], connection=redis_conn)
worker.work()
