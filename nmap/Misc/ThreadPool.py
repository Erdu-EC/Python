#From threading import *
import threading, sys
from threading import Thread, Semaphore, Lock

class ThreadPool(object):
    def __init__(self, num_threads):
        self.num_threads = num_threads
        self.threads = list()
        self.actions = list()
        self.semaforo = Semaphore(0)
        self.lock = Lock()
        self.finish = Lock()
    
    def AddThread(self):
        hilo = Thread(target=self.worker)
        self.threads.append(hilo)
        hilo.start()
        
    def addAction(self, action:callable, args:tuple = None, name = None):
        if  len(self.threads) < self.num_threads:
            self.AddThread()

        self.actions.append((action, args, name))
        self.semaforo.release()

    def worker(self):
        while True:
            #Si hay acciones en lista, no se bloqueara
            if not self.semaforo.acquire(timeout=1):
                #Comprobando si se cerro el pool y no hay acciones
                if (len(self.actions) == 0) and self.finish.locked():
                    break
                else:
                    continue

            #Extrayendo accion (Exclusion)
            self.lock.acquire()
            accion = self.actions.pop(0)
            self.lock.release()

            #Realizando accion
            if (accion != None):
                threading.current_thread().setName(accion[2])

                if accion[1] != None:
                    if isinstance(accion[1], dict):
                        accion[0](**accion[1])
                    else:
                        accion[0](*accion[1])
                else:
                    accion[0]()

            #Comprobando si se cerro el pool y no hay acciones
            if (len(self.actions) == 0) and self.finish.locked():
                break
        
        #Si termino, eliminando de la lista de hilos
        #self.threads.remove(threading.current_thread())
        
    def close(self):
        self.finish.acquire()

        for hilo in self.threads:
            if hilo.isAlive():
                hilo.join()

        self.threads.clear()
        self.finish.release()

