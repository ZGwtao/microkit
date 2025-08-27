
- procedure of trusted loading
    - get elf
    - parse elf header and check integrity
    - check signature and verify access rights
    - parse access rights
    - revoke capabilities
    - create mappings (as required)
    - load elf to template
    - set template to start

- thought
    -> have a trusted loader as r/x in the address space of the template PD
        -> code sections r/x, mappings (frames) caps in the parent PD -- unchangeable
        -> data sections rw(x), mappings ?

    -> once an elf is sent
    -> the parent PD load the elf into the template
        => here we need to backup the resource
        => so we back up all capabilities in a "background" CNode
        => and mint the CNode cap to the template's CNode
        => also the cap of the template CNode itself
            -> the trusted loader should revoke the access to both CNode after loading...
    -> start executing the trusted loader
    -> trusted loader check elf header and integrity
    -> check signature and verify access rights
        -> requires a hash and key?
        -> so the parent PD should load the hash/key into the data section of trusted loader each time
    -> after all checks, remove the hash/key ...
        -> can just simply clean up...
        -> if any of the check fails, use PPC to call the parent PD...
            -> in such a case, an endpoint is required
            -> but we dont want the client code to pretend to be a trusted loader
            -> so if the checks are finished, revoke the ep (or place it in the background CNode)
    -> with given access rights
        -> remove the access from last time?
        -> for the caps, yes, it is easy
        (record the context of access rights in a shared memory between the template and the parent)
        (once done with initialisation, unmap this from the template, while still recorded in the parent)
        (next time before starting the template, the parent will redo mapping for the context)
        -> mint required capabilities
        -> create required mappings

    -> after loading everything
        -> unmap data regions (run on stack)
        -> revoke access to the background CNode
        -> revoke access to its own CNode
        -> switch to the client code (or a small prologue that zeroing the stack of the trusted loader)

    -> the trusted loader can have two stack
        -> one stack is for verifying signature, and if all done, switch to new stack


    init:
        - the monitor pd maps the code section of the trusted loader as r/x
        

each time we kill a connection, we need to not just silence the client side, but signals the servers to let them know that the connection status is changed.

the big picture is, seL4 works well in embedded systems, but not server class system yet. we want to prove that we can build system on seL4 to live well in server class systems securely and efficiently. such as system should be secure enough and provable. With this aim, we build a proto system for serverclass machine, and the system should be simple enough to be verified.
