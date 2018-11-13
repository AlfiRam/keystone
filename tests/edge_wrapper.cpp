#include "edge_wrapper.h"
#include <string.h>
/* Really all of this file should be autogenerated, that will happen
   eventually. */

#define OCALL_PRINT_BUFFER 1
#define OCALL_PRINT_VALUE 2
#define OCALL_COPY_REPORT 3
#define OCALL_GET_STRING 4


int edge_init(Keystone* enclave){

  enclave->registerOcallDispatch(incoming_call_dispatch);
  register_call(OCALL_PRINT_BUFFER, print_buffer_wrapper);
  register_call(OCALL_PRINT_VALUE, print_value_wrapper);
  register_call(OCALL_COPY_REPORT, copy_report_wrapper);
  register_call(OCALL_GET_STRING, get_host_string_wrapper);
}

// TODO: again, should be autogenerated
size_t pbw_data_len = 64;


// TODO: This should be autogenerated
void print_buffer_wrapper(void* shared_buffer, size_t shared_buffer_size)
{
  /* For now we assume the call struct is at the front of the shared
   * buffer. This will have to change to allow nested calls. */
  struct edge_call_t* edge_call = (struct edge_call_t*)shared_buffer;

  uintptr_t data_section;
  unsigned long ret_val;
  if(edge_call_get_ptr_from_offset((uintptr_t)shared_buffer, shared_buffer_size,
				     edge_call->call_arg_offset, pbw_data_len,
				     &data_section) != 0){
    // Need to raise some error somewhere, oh well
    edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
    return;
  }

  ret_val = print_buffer((char*)data_section);
  // We are done with the data section for args, use as return region
  // TODO safety check?
  memcpy((void*)data_section, &ret_val, sizeof(unsigned long));  
  edge_call->return_data.call_status = CALL_STATUS_OK;

  if(edge_call_get_offset_from_ptr((uintptr_t)shared_buffer, shared_buffer_size,
				   data_section, sizeof(unsigned long),
				   &(edge_call->return_data.call_ret_offset)) != 0){
    
    edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
  }

  return;
}

void print_value_wrapper(void* shared_buffer, size_t shared_buffer_size)
{
  /* For now we assume the call struct is at the front of the shared
   * buffer. This will have to change to allow nested calls. */
  struct edge_call_t* edge_call = (struct edge_call_t*)shared_buffer;

  uintptr_t data_section;
  unsigned long ret_val;
  if(edge_call_get_ptr_from_offset((uintptr_t)shared_buffer, shared_buffer_size,
				     edge_call->call_arg_offset, pbw_data_len,
				     &data_section) != 0){
    // Need to raise some error somewhere, oh well
    edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
    return;
  }

  print_value(*(unsigned long*)data_section);

  edge_call->return_data.call_status = CALL_STATUS_OK;

  return;
}

void copy_report_wrapper(void* shared_buffer, size_t shared_buffer_size)
{
  struct edge_call_t* edge_call = (struct edge_call_t*) shared_buffer;

  uintptr_t data_section;
  unsigned long ret_val;
  if(edge_call_get_ptr_from_offset((uintptr_t) shared_buffer, shared_buffer_size,
        edge_call->call_arg_offset, pbw_data_len,
        &data_section) != 0) {
    edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
    return;
  }
  
  copy_report((void*)data_section);

  edge_call->return_data.call_status = CALL_STATUS_OK;

  return;
}

void get_host_string_wrapper(void* shared_buffer, size_t shared_buffer_size)
{
  struct edge_call_t* edge_call = (struct edge_call_t*) shared_buffer;

  uintptr_t data_section;

  data_section = (uintptr_t)shared_buffer+sizeof(struct edge_call_t);
  unsigned long ret_val;

  host_packaged_str_t hps;

  get_host_string(&hps);


  /* Now we will repackage this into offsets for the app, and load all
     of it into the shared data region */
  app_packaged_str_t aps;
  
  /* Setup the offset for the app packaged string */
  if(edge_call_get_offset_from_ptr((uintptr_t) shared_buffer, shared_buffer_size,
				   data_section, sizeof(app_packaged_str_t),
				   &edge_call->return_data.call_ret_offset) != 0) {
    edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
    return;
  }

  /* Setup the offset for the actual string data */
  uintptr_t str_shared_ptr = data_section+sizeof(app_packaged_str_t);
  
  /* TODO we want a better recovery mode here if the input string is
     too long */
  if(edge_call_get_offset_from_ptr((uintptr_t) shared_buffer, shared_buffer_size,
				   str_shared_ptr, hps.len,
				   &aps.str_offset) != 0) {
    edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
    return;
  }

  /* Setup the rest of the aps, and copy it */
  aps.len = hps.len;
  memcpy((void*)data_section, (void*)&aps, sizeof(app_packaged_str_t));

  /* Copy the string */  
  memcpy((void*)str_shared_ptr, (void*)hps.str, hps.len);
  
  edge_call->return_data.call_status = CALL_STATUS_OK;

  return;
  
  
}
