#!/usr/bin/env python3
"""
Performance Optimizer - CPU & RAM Management
Prevents system slowdown during intensive scanning operations
"""

import os
import gc
import time
import psutil
import threading
import logging
from queue import Queue
from typing import Callable, List, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)


class PerformanceOptimizer:
    """
    Manages CPU and RAM usage to prevent system slowdown
    
    Features:
    - Intelligent thread pool sizing
    - Memory usage monitoring
    - Automatic garbage collection
    - Batch processing for large datasets
    - CPU throttling when needed
    """
    
    def __init__(self, max_cpu_percent: int = 70, max_memory_percent: int = 70):
        """
        Args:
            max_cpu_percent: Maximum CPU usage allowed (0-100)
            max_memory_percent: Maximum RAM usage allowed (0-100)
        """
        self.max_cpu_percent = max_cpu_percent
        self.max_memory_percent = max_memory_percent
        
        # Get system info
        self.cpu_count = os.cpu_count() or 4
        self.total_ram = psutil.virtual_memory().total
        
        # Thread pool settings
        self.max_workers = self._calculate_optimal_workers()
        
        # Monitoring
        self.monitoring = False
        self.monitor_thread = None
        
        logger.info(f"Performance Optimizer initialized:")
        logger.info(f"  CPUs: {self.cpu_count}")
        logger.info(f"  RAM: {self.total_ram / (1024**3):.1f} GB")
        logger.info(f"  Max workers: {self.max_workers}")
    
    def _calculate_optimal_workers(self) -> int:
        """
        Calculate optimal number of worker threads based on:
        - CPU count
        - Available RAM
        - Current system load
        """
        # Start with CPU count
        optimal = self.cpu_count
        
        # Reduce if limited RAM
        available_gb = psutil.virtual_memory().available / (1024**3)
        if available_gb < 2:
            optimal = max(2, optimal // 2)
        elif available_gb < 4:
            optimal = max(4, int(optimal * 0.75))
        
        # Cap at reasonable maximum
        optimal = min(optimal, 16)
        optimal = max(optimal, 2)  # At least 2 workers
        
        return optimal
    
    def get_current_usage(self) -> dict:
        """Get current CPU and RAM usage"""
        cpu_percent = psutil.cpu_percent(interval=0.1)
        mem = psutil.virtual_memory()
        
        return {
            'cpu_percent': cpu_percent,
            'memory_percent': mem.percent,
            'memory_available_gb': mem.available / (1024**3),
            'memory_used_gb': mem.used / (1024**3)
        }
    
    def should_throttle(self) -> bool:
        """Check if we should throttle operations"""
        usage = self.get_current_usage()
        
        if usage['cpu_percent'] > self.max_cpu_percent:
            logger.warning(f"High CPU usage: {usage['cpu_percent']:.1f}%")
            return True
        
        if usage['memory_percent'] > self.max_memory_percent:
            logger.warning(f"High memory usage: {usage['memory_percent']:.1f}%")
            return True
        
        return False
    
    def throttle_if_needed(self, sleep_time: float = 0.5):
        """Sleep if system is under heavy load"""
        if self.should_throttle():
            logger.info(f"Throttling for {sleep_time}s...")
            time.sleep(sleep_time)
            gc.collect()  # Force garbage collection
    
    def process_in_batches(self, items: List[Any], 
                           process_func: Callable, 
                           batch_size: int = None,
                           progress_callback: Callable = None) -> List[Any]:
        """
        Process items in batches with resource monitoring
        
        Args:
            items: List of items to process
            process_func: Function to process each item
            batch_size: Items per batch (auto-calculated if None)
            progress_callback: Optional callback(current, total)
            
        Returns:
            List of results
        """
        if not items:
            return []
        
        # Auto-calculate batch size based on available memory
        if batch_size is None:
            available_gb = psutil.virtual_memory().available / (1024**3)
            if available_gb > 8:
                batch_size = 1000
            elif available_gb > 4:
                batch_size = 500
            elif available_gb > 2:
                batch_size = 200
            else:
                batch_size = 100
        
        results = []
        total_items = len(items)
        
        logger.info(f"Processing {total_items} items in batches of {batch_size}")
        
        for i in range(0, total_items, batch_size):
            batch = items[i:i + batch_size]
            
            # Process batch
            batch_results = self._process_batch_parallel(batch, process_func)
            results.extend(batch_results)
            
            # Progress callback
            if progress_callback:
                progress_callback(min(i + batch_size, total_items), total_items)
            
            # Throttle if needed
            self.throttle_if_needed(sleep_time=0.2)
            
            # Periodic garbage collection
            if i % (batch_size * 5) == 0:
                gc.collect()
        
        return results
    
    def _process_batch_parallel(self, batch: List[Any], 
                                process_func: Callable) -> List[Any]:
        """Process a batch using thread pool"""
        results = []
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(process_func, item): item for item in batch}
            
            for future in as_completed(futures):
                try:
                    result = future.result(timeout=30)
                    if result is not None:
                        results.append(result)
                except Exception as e:
                    logger.debug(f"Batch processing error: {e}")
        
        return results
    
    def process_with_queue(self, items: List[Any],
                          process_func: Callable,
                          progress_callback: Callable = None) -> List[Any]:
        """
        Process items using a queue-based approach (memory efficient)
        
        Args:
            items: List of items to process
            process_func: Function to process each item
            progress_callback: Optional callback(current, total)
            
        Returns:
            List of results
        """
        queue = Queue(maxsize=self.max_workers * 2)
        results = []
        results_lock = threading.Lock()
        total_items = len(items)
        processed = [0]  # Use list to allow modification in nested function
        
        def worker():
            while True:
                item = queue.get()
                if item is None:
                    break
                
                try:
                    result = process_func(item)
                    if result is not None:
                        with results_lock:
                            results.append(result)
                except Exception as e:
                    logger.debug(f"Queue processing error: {e}")
                finally:
                    processed[0] += 1
                    if progress_callback:
                        progress_callback(processed[0], total_items)
                    queue.task_done()
        
        # Start workers
        threads = []
        for _ in range(self.max_workers):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            threads.append(t)
        
        # Feed queue
        for item in items:
            queue.put(item)
            
            # Throttle queue feeding if needed
            if self.should_throttle():
                time.sleep(0.1)
        
        # Wait for completion
        queue.join()
        
        # Stop workers
        for _ in range(self.max_workers):
            queue.put(None)
        for t in threads:
            t.join()
        
        return results
    
    def optimize_memory(self):
        """Force memory optimization"""
        gc.collect()
        
        # Clear caches if available
        try:
            import ctypes
            if hasattr(ctypes, 'windll'):
                ctypes.windll.kernel32.SetProcessWorkingSetSize(-1, -1, -1)
        except:
            pass
        
        usage = self.get_current_usage()
        logger.info(f"Memory optimized: {usage['memory_used_gb']:.1f} GB used")
    
    def start_monitoring(self, interval: int = 10):
        """
        Start background resource monitoring
        
        Args:
            interval: Check interval in seconds
        """
        if self.monitoring:
            return
        
        self.monitoring = True
        
        def monitor():
            while self.monitoring:
                usage = self.get_current_usage()
                
                if usage['cpu_percent'] > self.max_cpu_percent:
                    logger.warning(f"⚠️  High CPU: {usage['cpu_percent']:.1f}%")
                
                if usage['memory_percent'] > self.max_memory_percent:
                    logger.warning(f"⚠️  High RAM: {usage['memory_percent']:.1f}%")
                    self.optimize_memory()
                
                time.sleep(interval)
        
        self.monitor_thread = threading.Thread(target=monitor, daemon=True)
        self.monitor_thread.start()
        logger.info("Resource monitoring started")
    
    def stop_monitoring(self):
        """Stop background monitoring"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2)
        logger.info("Resource monitoring stopped")
    
    def get_recommendations(self) -> dict:
        """Get performance recommendations"""
        usage = self.get_current_usage()
        recommendations = []
        
        if usage['memory_available_gb'] < 1:
            recommendations.append("⚠️  Low memory available - consider closing other applications")
        
        if usage['cpu_percent'] > 80:
            recommendations.append("⚠️  High CPU usage - reduce concurrent operations")
        
        if self.cpu_count < 4:
            recommendations.append("💡 Limited CPU cores - scan may take longer")
        
        if not recommendations:
            recommendations.append("✅ System resources are optimal")
        
        return {
            'usage': usage,
            'recommendations': recommendations,
            'optimal_workers': self.max_workers
        }


# Test module
if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    print("=" * 70)
    print("PERFORMANCE OPTIMIZER - TEST")
    print("=" * 70)
    
    optimizer = PerformanceOptimizer(max_cpu_percent=70, max_memory_percent=70)
    
    print("\n1. System Information:")
    print("-" * 70)
    usage = optimizer.get_current_usage()
    for key, value in usage.items():
        print(f"   {key}: {value}")
    
    print("\n2. Performance Recommendations:")
    print("-" * 70)
    recs = optimizer.get_recommendations()
    for rec in recs['recommendations']:
        print(f"   {rec}")
    
    print("\n3. Testing Batch Processing:")
    print("-" * 70)
    
    # Test data
    test_items = list(range(100))
    
    def test_process(item):
        time.sleep(0.01)  # Simulate work
        return item * 2
    
    def progress(current, total):
        if current % 20 == 0 or current == total:
            print(f"   Progress: {current}/{total}")
    
    results = optimizer.process_in_batches(
        test_items, 
        test_process, 
        batch_size=20,
        progress_callback=progress
    )
    
    print(f"   Processed {len(results)} items")
    
    print("\n4. Testing Resource Monitoring:")
    print("-" * 70)
    optimizer.start_monitoring(interval=2)
    time.sleep(5)
    optimizer.stop_monitoring()
    
    print("\n5. Memory Optimization:")
    print("-" * 70)
    before = optimizer.get_current_usage()
    print(f"   Before: {before['memory_used_gb']:.2f} GB")
    optimizer.optimize_memory()
    after = optimizer.get_current_usage()
    print(f"   After: {after['memory_used_gb']:.2f} GB")
    
    print("\n" + "=" * 70)
    print("✅ Performance optimizer test complete!")
    print("=" * 70)
