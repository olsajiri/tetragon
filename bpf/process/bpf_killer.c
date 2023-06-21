#include "bpf_killer.h"

__attribute__((section("kprobe/killer"), used)) int
killer(void *ctx)
{
	__u64 id = get_current_pid_tgid();
	struct killer_data *data;

	data = map_lookup_elem(&killer_data, &id);
	if (!data)
		return 0;

	if (data->error)
		override_return(ctx, data->error);
	if (data->signal)
		send_signal(data->signal);

	map_delete_elem(&killer_data, &id);
	return 0;
}
