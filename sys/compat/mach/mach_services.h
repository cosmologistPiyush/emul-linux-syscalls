/* $NetBSD: mach_services.h,v 1.12 2003/12/24 23:22:22 manu Exp $ */

/*
 * Mach services prototypes.
 *
 * DO NOT EDIT -- this file is automatically generated.
 * created from NetBSD: mach_services.master,v 1.8 2003/12/09 12:13:44 manu Exp 
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: mach_services.h,v 1.12 2003/12/24 23:22:22 manu Exp $");

#include <compat/mach/mach_types.h>
#include <compat/mach/mach_message.h>

int mach_host_info(struct mach_trap_args *);
int mach_host_page_size(struct mach_trap_args *);
int mach_host_get_io_master(struct mach_trap_args *);
int mach_host_get_clock_service(struct mach_trap_args *);
int mach_bootstrap_look_up(struct mach_trap_args *);
int mach_clock_get_time(struct mach_trap_args *);
int mach_exception_raise(struct mach_trap_args *);
int mach_exception_raise_state(struct mach_trap_args *);
int mach_exception_raise_state_identity(struct mach_trap_args *);
int mach_io_object_get_class(struct mach_trap_args *);
int mach_io_object_conforms_to(struct mach_trap_args *);
int mach_io_iterator_next(struct mach_trap_args *);
int mach_io_iterator_reset(struct mach_trap_args *);
int mach_io_service_get_matching_services(struct mach_trap_args *);
int mach_io_registry_entry_get_property(struct mach_trap_args *);
int mach_io_registry_entry_from_path(struct mach_trap_args *);
int mach_io_registry_entry_get_properties(struct mach_trap_args *);
int mach_io_registry_entry_get_child_iterator(struct mach_trap_args *);
int mach_io_registry_entry_get_parent_iterator(struct mach_trap_args *);
int mach_io_service_open(struct mach_trap_args *);
int mach_io_service_close(struct mach_trap_args *);
int mach_io_connect_get_service(struct mach_trap_args *);
int mach_io_connect_set_notification_port(struct mach_trap_args *);
int mach_io_connect_map_memory(struct mach_trap_args *);
int mach_io_connect_add_client(struct mach_trap_args *);
int mach_io_connect_set_properties(struct mach_trap_args *);
int mach_io_connect_method_scalari_scalaro(struct mach_trap_args *);
int mach_io_connect_method_scalari_structo(struct mach_trap_args *);
int mach_io_connect_method_scalari_structi(struct mach_trap_args *);
int mach_io_connect_method_structi_structo(struct mach_trap_args *);
int mach_io_registry_entry_get_path(struct mach_trap_args *);
int mach_io_registry_get_root_entry(struct mach_trap_args *);
int mach_io_registry_entry_create_iterator(struct mach_trap_args *);
int mach_io_registry_entry_get_name_in_plane(struct mach_trap_args *);
int mach_io_service_add_interest_notification(struct mach_trap_args *);
int mach_io_registry_entry_get_location_in_plane(struct mach_trap_args *);
int mach_port_type(struct mach_trap_args *);
int mach_port_allocate(struct mach_trap_args *);
int mach_port_destroy(struct mach_trap_args *);
int mach_port_deallocate(struct mach_trap_args *);
int mach_port_move_member(struct mach_trap_args *);
int mach_port_request_notification(struct mach_trap_args *);
int mach_port_insert_right(struct mach_trap_args *);
int mach_port_get_attributes(struct mach_trap_args *);
int mach_port_set_attributes(struct mach_trap_args *);
int mach_port_insert_member(struct mach_trap_args *);
int mach_task_terminate(struct mach_trap_args *);
int mach_task_threads(struct mach_trap_args *);
int mach_ports_lookup(struct mach_trap_args *);
int mach_task_info(struct mach_trap_args *);
int mach_task_suspend(struct mach_trap_args *);
int mach_task_resume(struct mach_trap_args *);
int mach_task_get_special_port(struct mach_trap_args *);
int mach_task_set_special_port(struct mach_trap_args *);
int mach_thread_create_running(struct mach_trap_args *);
int mach_task_set_exception_ports(struct mach_trap_args *);
int mach_task_get_exception_ports(struct mach_trap_args *);
int mach_semaphore_create(struct mach_trap_args *);
int mach_semaphore_destroy(struct mach_trap_args *);
int mach_thread_get_state(struct mach_trap_args *);
int mach_thread_set_state(struct mach_trap_args *);
int mach_thread_suspend(struct mach_trap_args *);
int mach_thread_resume(struct mach_trap_args *);
int mach_thread_abort(struct mach_trap_args *);
int mach_thread_info(struct mach_trap_args *);
int mach_thread_policy(struct mach_trap_args *);
int mach_vm_region(struct mach_trap_args *);
int mach_vm_allocate(struct mach_trap_args *);
int mach_vm_deallocate(struct mach_trap_args *);
int mach_vm_protect(struct mach_trap_args *);
int mach_vm_inherit(struct mach_trap_args *);
int mach_vm_read(struct mach_trap_args *);
int mach_vm_write(struct mach_trap_args *);
int mach_vm_copy(struct mach_trap_args *);
int mach_vm_msync(struct mach_trap_args *);
int mach_vm_map(struct mach_trap_args *);
int mach_vm_machine_attribute(struct mach_trap_args *);
int mach_vm_region_64(struct mach_trap_args *);
int mach_make_memory_entry_64(struct mach_trap_args *);
