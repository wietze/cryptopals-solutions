def challenge(set, challenge):
    def outer_wrapper(code):
        def inner_wrapper():
            print("=========================")
            print("SET {}, CHALLENGE {}".format(set, challenge))
            print("=========================")
            code()
            print("")
        return inner_wrapper
    return outer_wrapper
