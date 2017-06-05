import sys, traceback
from colorama import init, Fore, Back
init(convert=True)

def challenge(set, challenge):
    def outer_wrapper(code):
        def inner_wrapper():
            print(Back.WHITE + Fore.BLACK + "  SET {}, CHALLENGE {}  ".format(set, challenge).ljust(35) + Back.RESET + Fore.RESET)
            try:
                code()
            except Exception:
                print(Fore.RED + "FAIL" + Fore.RESET)
                traceback.print_exc(file=sys.stdout)
                sys.exit(-1)
            print("")
        return inner_wrapper
    return outer_wrapper

def assert_true(condition):
    if condition:
        print(Fore.GREEN + "Pass" + Fore.RESET)
    else:
        print(Fore.RED + "FAIL" + Fore.RESET)
        sys.exit(-1)

