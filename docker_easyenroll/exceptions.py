class TransientError(Exception):
    ''' An exception has occurred but it is transient - request can safely be retried '''


class EnrollmentFailure(Exception):
    ''' Target server is not in an enrollable state '''
