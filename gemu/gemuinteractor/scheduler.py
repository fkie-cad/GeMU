import datetime
import time
from multiprocessing import Pool


class Instance:
    def __init__(self, vm):
        self.vm = vm
        self.process = None

class Scheduler:
    def __init__(self, target, vms):
        self.vm_instances = self.initiate_vms(vms)
        self.target = target

    @staticmethod
    def initiate_vms(vms):
        free_vms = set()
        for vm in vms:
            print("added VM", vm)
            free_vms.add(Instance(vm))
        return free_vms

    def process_samples(self, samples):
        with Pool(processes=len(self.vm_instances)) as pool:
            for sample in samples:
                started = False
                print(sample)
                while True:
                    for vm_instance in self.vm_instances:
                        if (not vm_instance.process) or vm_instance.process.ready():
                            vm_instance.process = pool.apply_async(self.target, args=(sample, vm_instance.vm))
                            time.sleep(2)
                            print(f"started {sample} with {vm_instance.vm} at {datetime.datetime.now()}")
                            started = True
                            break
                    else:
                        time.sleep(1)
                    if started:
                        break

            for vm_instance in self.vm_instances:
                # Nothing to do if no process was ever started
                if vm_instance.process is not None:
                    vm_instance.process.wait()
