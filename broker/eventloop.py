import select


class EventLoop(object):
    """
    An epoll-based event loop.
    """

    def __init__(self):
        """
        Constructs the event loop.
        """

        self.pollables = {}
        self.poller = select.epoll()

    def register(self, pollable, file_object, flags):
        """
        Registers a new pollable into the event loop.

        :param pollable: Pollable instance
        :param file_object: File-like object or file descriptor
        :param flags: Epoll flags
        """

        if hasattr(file_object, 'fileno'):
            file_object = file_object.fileno()

        self.poller.register(file_object, flags)
        self.pollables[file_object] = pollable

    def unregister(self, fd):
        """
        Unregisters an existing file descriptor.

        :param fd: File descriptor
        """

        self.poller.unregister(fd)
        del self.pollables[fd]

    def start(self):
        """
        Starts the event loop.
        """

        while True:
            for fd, event in self.poller.poll():
                pollable = self.pollables.get(fd, None)
                if not pollable:
                    continue

                if event & select.EPOLLIN:
                    pollable.read()
