"""Отдельный worker; очередь PostgreSQL будет подключена следующим этапом P0."""
import logging, time
logging.basicConfig(level=logging.INFO)
logger=logging.getLogger("secworkflow.worker")
def main():
    logger.info("Worker started; persistent queue adapter is pending.")
    while True: time.sleep(5)
if __name__=="__main__": main()
