import os
import sys
import time
import random
import asyncio

sys.path.insert(0, r"c:\Users\akhand_admin\Downloads\blindlog\src")

from blindlog.core import BlindLogger

logger = BlindLogger(secret_key="enterprise-stress-secret")
logger.config.sensitive_keys.update({"credit_card", "credentials", "session_id"})

ROUNDS = 50_000

def generate_payload():
    return {
        "event_id": random.randint(1000, 99999),
        "timestamp": time.time(),
        "level": "ERROR",
        "user": {
            "name": f"User_{random.randint(1,100)}",
            "email": f"test.user.{random.randint(1,10000)}@example.com",
            "credit_card": f"4{random.randint(100,999)}-{random.randint(1000,9999)}-{random.randint(1000,9999)}-{random.randint(1000,9999)}"
        },
        "credentials": {
            "session_token": "".join(random.choice("abcdef0123456789") for _ in range(32)),
        },
        "metadata": {
            "browser": "Chrome",
            "raw_log": f"Failure connecting to DB for test@domain.com. Card 5123-1111-2222-3333 declined."
        }
    }

print(f"Generating {ROUNDS:,} realistic JSON payloads representing heavy concurrent API traffic...")
# Pre-allocate to prevent generation time from impacting benchmark timing
pool = [generate_payload() for _ in range(ROUNDS)]

def run_synchronous_benchmark():
    print(f"\n[1] Starting Synchronous CPU Hot-Path Benchmark ({ROUNDS:,} Iterations)...")
    start = time.process_time()
    actual_start = time.time()
    
    for item in pool:
        logger.mask(item)
        
    end = time.process_time()
    actual_end = time.time()
    
    total_cpu = end - start
    total_wall = actual_end - actual_start
    rops = ROUNDS / total_wall
    
    print("--- Results ---")
    print(f"Wall Clock Time:  {total_wall:.4f} seconds")
    print(f"CPU Time Used:    {total_cpu:.4f} seconds")
    print(f"Latency per mask: {(total_wall / ROUNDS) * 1000:.4f} milliseconds")
    print(f"Throughput (RPS): {rops:,.0f} operations/sec")


async def run_asgi_simulation_benchmark():
    print(f"\n[2] Starting ASGI Multithreading Simulation ({ROUNDS:,} Iterations)...")
    print("Simulating FastAPI ThreadPool dispatch (4 threads bounding GIL execution)")
    
    actual_start = time.time()
    
    def process_chunk(chunk):
        for item in chunk:
            logger.mask(item)
            
    chunk_size = 5_000
    chunks = [pool[i:i + chunk_size] for i in range(0, len(pool), chunk_size)]
    
    from concurrent.futures import ThreadPoolExecutor
    loop = asyncio.get_running_loop()
    with ThreadPoolExecutor(max_workers=4) as executor:
        await asyncio.gather(*(loop.run_in_executor(executor, process_chunk, chunk) for chunk in chunks))
    
    actual_end = time.time()
    total_wall = actual_end - actual_start
    rops = ROUNDS / total_wall
    
    print("--- Results ---")
    print(f"Wall Clock Time:  {total_wall:.4f} seconds")
    print(f"Latency per mask: {(total_wall / ROUNDS) * 1000:.4f} milliseconds")
    print(f"Throughput (RPS): {rops:,.0f} operations/sec")


if __name__ == "__main__":
    run_synchronous_benchmark()
    asyncio.run(run_asgi_simulation_benchmark())
    print("\nBenchmark Complete.")
