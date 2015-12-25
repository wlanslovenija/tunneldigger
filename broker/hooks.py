import fcntl
import io
import os
import select
import signal
import subprocess
import logging

# Logger.
logger = logging.getLogger("tunneldigger.hooks")


class HookProcess(object):
    """
    Class used for communication with external hook processes.
    """

    def __init__(self, name, script, args):
        """
        Constructs a hook process instance.

        :param name: Hook name
        :param script: Script to execute
        :param args: List of script arguments
        """

        self.name = name
        self.process = subprocess.Popen(
            [script] + [str(x) for x in args],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.buffer = io.BytesIO()

    def register(self, event_loop):
        """
        Registers the hook process into an event loop.

        :param event_loop: Event loop instance
        """

        # Make the file descriptors non-blocking.
        flags = fcntl.fcntl(self.process.stdout, fcntl.F_GETFL)
        fcntl.fcntl(self.process.stdout, fcntl.F_SETFL, flags | os.O_NONBLOCK)
        flags = fcntl.fcntl(self.process.stderr, fcntl.F_GETFL)
        fcntl.fcntl(self.process.stderr, fcntl.F_SETFL, flags | os.O_NONBLOCK)

        # Register the file descriptors with the event loop.
        event_loop.register(self, self.process.stdout, select.EPOLLIN)
        event_loop.register(self, self.process.stderr, select.EPOLLIN)
        self.event_loop = event_loop

    def close(self):
        """
        Closes the hook process.
        """

        for line in self.buffer.getvalue().split('\n'):
            if not line:
                continue

            logger.info('(%s/%d) %s' % (self.name, self.process.pid, line))

        del self.buffer
        self.event_loop.unregister(self.process.stdout.fileno())
        self.event_loop.unregister(self.process.stderr.fileno())

        # Kill the process in case it is still running.
        try:
            self.process.kill()
        except OSError:
            pass

        self.process.poll()

    def read(self, file_object):
        """
        Called when new data is available for reading from the hook process.
        """

        try:
            data = file_object.read()
            if data:
                self.buffer.write(data)

            # Check if the process has terminated.
            self.process.poll()
            if self.process.returncode is not None:
                self.close()
        except IOError:
            pass


class HookManager(object):
    """
    Manages hooks.
    """

    def __init__(self, event_loop):
        """
        Constructs a new hook manager instance.

        :param event_loop: Event loop instance
        """

        self.event_loop = event_loop
        self.hooks = {}
        self.processes = {}

        # Create a file descriptor so we can get notified of SIGCHLD signals in the
        # context of the event loop (and not in an arbitrary location).
        pipe_r, pipe_w = os.pipe()
        flags = fcntl.fcntl(pipe_w, fcntl.F_GETFL, 0)
        flags = fcntl.fcntl(pipe_w, fcntl.F_SETFL, flags | os.O_NONBLOCK)


        def sigchld_handler(signal_number, frame):
            os.write(pipe_w, '\x00')

        signal.signal(signal.SIGCHLD, sigchld_handler)
        event_loop.register(self, pipe_r, select.EPOLLIN)

    def register_hook(self, name, script):
        """
        Registers a new hook under a given name.

        :param name: Hook name
        :param script: Script that should be executed
        """

        self.hooks[name] = script

    def run_hook(self, name, *args):
        """
        Runs a given hook.

        :param name: Hook name
        """

        script = self.hooks.get(name, None)
        if not script:
            return

        logger.info("Running hook '%s' via script '%s %s'." % (name, script, " ".join([str(x) for x in args])))
        try:
            process = HookProcess(name, script, args)
            process.register(self.event_loop)
            self.processes[process.process.pid] = process
        except OSError, e:
            logger.error("Error while executing script '%s': %s" % (script, e))

    def close(self):
        os.close(self.sigchld_fd)

    def read(self, file_object):
        """
        Handles SIGCHLD notifications.
        """

        os.read(file_object, 1)

        while True:
            try:
                pid, returncode = os.waitpid(-1, os.WNOHANG)
                if not pid:
                    return

                process = self.processes.get(pid)
                if not process:
                    continue

                try:
                    process.close()
                finally:
                    del self.processes[pid]
            except OSError:
                return
