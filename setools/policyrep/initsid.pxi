# Copyright 2014, Tresys Technology, LLC
# Copyright 2017-2018, Chris PeBenito <pebenito@ieee.org>
#
# This file is part of SETools.
#
# SETools is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation, either version 2.1 of
# the License, or (at your option) any later version.
#
# SETools is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with SETools.  If not, see
# <http://www.gnu.org/licenses/>.
#

#
# Constants
#
# Binary policy does not contain the SID names
SELINUX_SIDNAMES = ("undefined", "kernel", "security", "unlabeled", "fs", "file", "file_labels",
    "init", "any_socket", "port", "netif", "netmsg", "node", "igmp_packet", "icmp_socket",
    "tcp_socket", "sysctl_modprobe", "sysctl", "sysctl_fs", "sysctl_kernel", "sysctl_net",
    "sysctl_net_unix", "sysctl_vm", "sysctl_dev", "kmod", "policy", "scmp_packet", "devnull")

SELINUX_SIDNAMES_DICT = dict((v, k) for k, v in enumerate(SELINUX_SIDNAMES))

XEN_SIDNAMES = ("xen", "dom0", "domxen", "domio", "unlabeled", "security", "irq", "iomem", "ioport",
    "device", "domU", "domDM")

XEN_SIDNAMES_DICT = dict((v, k) for k, v in enumerate(XEN_SIDNAMES))

#
# Classes
#
cdef class InitialSID(Ocontext):

    """An initial SID statement."""

    cdef str name

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.ocontext *symbol):
        """Factory function for creating InitialSID objects."""
        i = InitialSID()
        i.policy = policy
        i.handle = symbol

        if symbol.u.name:
            i.name = intern(symbol.u.name)
        elif policy.target_platform == PolicyTarget.selinux:
            i.name = SELINUX_SIDNAMES[<uint32_t>symbol.sid[0]]
        elif policy.target_platform == PolicyTarget.xen:
            i.name = XEN_SIDNAMES[<uint32_t>symbol.sid[0]]
        else:
            raise NotImplementedError

        return i

    def __str__(self):
        return self.name

    def statement(self):
        return "sid " + self.name + " " + str(Context.factory(self.policy, self.handle.context))

cdef class RawSIDIterator(OcontextIterator):
    """Iterator for initial SID statements in the policy."""

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.ocontext_t *head):
        """Factory function for creating initial SID iterators."""
        i = RawSIDIterator()
        i.policy = policy
        i.head = i.curr = head
        return i

    def __next__(self):
        super().__next__()
        return InitialSID.factory(self.policy, self.ocon)

cdef class InitialSIDIterator:

    """Iterator for initial SID statements in the policy."""

    cdef:
        list items

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.ocontext_t *head):
        """Factory function for creating initial SID iterators."""

        def sort_selinux_sid(item):
            name = str(item)
            return SELINUX_SIDNAMES_DICT[name] if name in SELINUX_SIDNAMES_DICT else len(SELINUX_SIDNAMES)

        def sort_xen_sid(item):
            name = str(item)
            return XEN_SIDNAMES_DICT[name] if name in XEN_SIDNAMES_DICT else len(XEN_SIDNAMES)
        
        raw_it = RawSIDIterator.factory(policy, head)
        i = InitialSIDIterator()
        if policy.target_platform == PolicyTarget.selinux:
            i.items = sorted(raw_it, key=sort_selinux_sid)
        elif policy.target_platform == PolicyTarget.xen:
            i.items = sorted(raw_it, key=sort_xen_sid)
        else:
            i.items = list(raw_it)

        return i

    def __iter__(self):
        return iter(self.items)

    def __len__(self):
        return len(self.items)
