import concurrent.futures
import threading
import queue
import logging
from typing import Any, Callable, List, Dict
from functools import partial

logger = logging.getLogger(__name__)

class ThreadPoolManager:
    """Thread pool manager for concurrent IOC scanning"""
    
    def __init__(self, max_workers: int = 10):
        self.max_workers = max_workers
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers)
        self.results_queue = queue.Queue()
        self._futures = []
        
    def submit_task(self, func: Callable, *args, **kwargs) -> concurrent.futures.Future:
        """Submit a task to the thread pool"""
        future = self.executor.submit(func, *args, **kwargs)
        self._futures.append(future)
        return future
        
    def map_tasks(self, func: Callable, iterable: List[Any]) -> List[Any]:
        """Map a function over an iterable using the thread pool"""
        return list(self.executor.map(func, iterable))
        
    def wait_for_tasks(self, timeout: float = None) -> List[Any]:
        """Wait for all submitted tasks to complete"""
        results = []
        try:
            done, not_done = concurrent.futures.wait(
                self._futures,
                timeout=timeout,
                return_when=concurrent.futures.ALL_COMPLETED
            )
            
            for future in done:
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    logger.error(f"Task error: {str(e)}", exc_info=True)
                    results.append(None)
                    
            if not_done:
                logger.warning(f"{len(not_done)} tasks did not complete within timeout")
                
        except Exception as e:
            logger.error(f"Error waiting for tasks: {str(e)}", exc_info=True)
            
        finally:
            self._futures.clear()
            
        return results
        
    def process_batch(self, func: Callable, items: List[Any], 
                     batch_size: int = 5, timeout: float = None) -> List[Any]:
        """Process items in batches using the thread pool"""
        results = []
        for i in range(0, len(items), batch_size):
            batch = items[i:i + batch_size]
            batch_futures = [self.submit_task(func, item) for item in batch]
            
            try:
                done, not_done = concurrent.futures.wait(
                    batch_futures,
                    timeout=timeout,
                    return_when=concurrent.futures.ALL_COMPLETED
                )
                
                for future in done:
                    try:
                        result = future.result()
                        results.append(result)
                    except Exception as e:
                        logger.error(f"Batch task error: {str(e)}", exc_info=True)
                        results.append(None)
                        
                if not_done:
                    logger.warning(f"{len(not_done)} batch tasks did not complete")
                    
            except Exception as e:
                logger.error(f"Error processing batch: {str(e)}", exc_info=True)
                
        return results
        
    def __enter__(self):
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.executor.shutdown(wait=True)
        
class IOCScannerPool:
    """Thread pool specifically for scanning IOCs"""
    
    def __init__(self, max_workers: int = 10, batch_size: int = 5):
        self.thread_pool = ThreadPoolManager(max_workers=max_workers)
        self.batch_size = batch_size
        
    async def scan_iocs(self, scan_func: Callable, iocs: List[str], 
                       timeout: float = None) -> Dict[str, Any]:
        """Scan multiple IOCs concurrently"""
        results = {}
        
        def _scan_wrapper(ioc: str) -> tuple:
            try:
                result = scan_func(ioc)
                return (ioc, result)
            except Exception as e:
                logger.error(f"Error scanning IOC {ioc}: {str(e)}", exc_info=True)
                return (ioc, None)
        
        # Process IOCs in batches
        batch_results = self.thread_pool.process_batch(
            _scan_wrapper,
            iocs,
            batch_size=self.batch_size,
            timeout=timeout
        )
        
        # Aggregate results
        for result in batch_results:
            if result:
                ioc, scan_result = result
                results[ioc] = scan_result
                
        return results
        
    def __enter__(self):
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.thread_pool.__exit__(exc_type, exc_val, exc_tb)
