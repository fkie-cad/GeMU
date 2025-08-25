import datetime
import time
from pathlib import Path
from multiprocessing import Pool
from multiprocessing.pool import AsyncResult
from typing import Callable, Iterable


class Instance:
    def __init__(self, vm: str):
        self.vm: str = vm # Name of the single vm config
        self.process: AsyncResult|None = None

class Scheduler:
    def __init__(self, target: Callable[[Path|str, str], None], vms):
        self._vm_instances: set[Instance] = self.initiate_vms(vms)
        self._target = target

    @staticmethod
    def initiate_vms(vms) -> set[Instance]:
        free_vms = set()
        for vm in vms:
            print("added VM", vm)
            free_vms.add(Instance(vm))
        return free_vms

    def process_samples(self, samples: Iterable[Path|str]):
        with Pool(processes=len(self._vm_instances)) as pool:
            for sample in samples:
                started = False
                print(sample)
                while True:
                    for vm_instance in self._vm_instances:
                        if (not vm_instance.process) or vm_instance.process.ready():
                            vm_instance.process = pool.apply_async(self._target, args=(sample, vm_instance.vm))
                            time.sleep(2)
                            print(f"started {sample} with {vm_instance.vm} at {datetime.datetime.now()}")
                            started = True
                            break
                    else:
                        time.sleep(1)
                    if started:
                        break

            for vm_instance in self._vm_instances:
                # Nothing to do if no process was ever started
                if vm_instance.process is not None:
                    vm_instance.process.wait()
