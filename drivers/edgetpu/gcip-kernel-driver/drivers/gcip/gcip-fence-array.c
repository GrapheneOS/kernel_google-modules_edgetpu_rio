// SPDX-License-Identifier: GPL-2.0-only
/*
 * Interface for the array of abstracted fences.
 *
 * Copyright (C) 2023 Google LLC
 */

#include <linux/kref.h>
#include <linux/slab.h>

#include <gcip/gcip-fence-array.h>
#include <gcip/gcip-fence.h>

struct gcip_fence_array *gcip_fence_array_create(int *fences, int num_fences, bool check_same_type)
{
	int i, ret;
	struct gcip_fence_array *fence_array;
	struct gcip_fence *fence;

	if (!fences && num_fences)
		return ERR_PTR(-EINVAL);

	fence_array = kzalloc(sizeof(*fence_array), GFP_KERNEL);
	if (!fence_array)
		return ERR_PTR(-ENOMEM);

	fence_array->fences = kcalloc(num_fences, sizeof(*fence_array->fences), GFP_KERNEL);
	if (!fence_array->fences) {
		ret = -ENOMEM;
		goto err_free_fence_array;
	}

	fence_array->same_type = true;

	for (i = 0; i < num_fences; i++) {
		fence = gcip_fence_fdget(fences[i]);
		if (IS_ERR(fence)) {
			ret = PTR_ERR(fence);
			goto err_put_fences;
		}

		if (i && fence_array->same_type && fence->type != fence_array->fences[0]->type) {
			/* Check whether all fences are the same type. */
			if (check_same_type) {
				ret = -EINVAL;
				gcip_fence_put(fence);
				goto err_put_fences;
			}
			fence_array->same_type = false;
		}

		fence_array->fences[i] = fence;
	}

	if (i && fence_array->same_type)
		fence_array->type = fence_array->fences[0]->type;

	fence_array->size = i;
	kref_init(&fence_array->kref);

	return fence_array;

err_put_fences:
	while (i--)
		gcip_fence_put(fence_array->fences[i]);
	kfree(fence_array->fences);
err_free_fence_array:
	kfree(fence_array);

	return ERR_PTR(ret);
}

static void gcip_fence_array_release(struct kref *kref)
{
	struct gcip_fence_array *fence_array = container_of(kref, struct gcip_fence_array, kref);
	int i;

	for (i = 0; i < fence_array->size; i++)
		gcip_fence_put(fence_array->fences[i]);
	kfree(fence_array->fences);
	kfree(fence_array);
}

struct gcip_fence_array *gcip_fence_array_get(struct gcip_fence_array *fence_array)
{
	if (!fence_array)
		return NULL;
	kref_get(&fence_array->kref);
	return fence_array;
}

void gcip_fence_array_put(struct gcip_fence_array *fence_array)
{
	if (fence_array)
		kref_put(&fence_array->kref, gcip_fence_array_release);
}

void gcip_fence_array_signal(struct gcip_fence_array *fence_array, int errno)
{
	int i;

	if (!fence_array)
		return;

	for (i = 0; i < fence_array->size; i++)
		gcip_fence_signal(fence_array->fences[i], errno);
}

void gcip_fence_array_waited(struct gcip_fence_array *fence_array)
{
	int i;

	if (!fence_array)
		return;

	for (i = 0; i < fence_array->size; i++)
		gcip_fence_waited(fence_array->fences[i]);
}

void gcip_fence_array_submit_signaler(struct gcip_fence_array *fence_array)
{
	int i;

	if (!fence_array)
		return;

	for (i = 0; i < fence_array->size; i++)
		gcip_fence_submit_signaler(fence_array->fences[i]);
}

void gcip_fence_array_submit_waiter(struct gcip_fence_array *fence_array)
{
	int i;

	if (!fence_array)
		return;

	for (i = 0; i < fence_array->size; i++)
		gcip_fence_submit_waiter(fence_array->fences[i]);
}

uint16_t *gcip_fence_array_get_iif_id(struct gcip_fence_array *fence_array, int *num_iif)
{
	uint16_t *iif_fences;
	int i, j;

	if (!fence_array)
		return NULL;

	*num_iif = 0;

	for (i = 0; i < fence_array->size; i++) {
		if (fence_array->fences[i]->type == GCIP_INTER_IP_FENCE)
			(*num_iif)++;
	}

	if (!(*num_iif))
		return NULL;

	iif_fences = kcalloc(*num_iif, sizeof(*iif_fences), GFP_KERNEL);
	if (!iif_fences)
		return ERR_PTR(-ENOMEM);

	for (i = 0, j = 0; i < fence_array->size; i++) {
		if (fence_array->fences[i]->type == GCIP_INTER_IP_FENCE)
			iif_fences[j++] = gcip_fence_get_iif_id(fence_array->fences[i]);
	}

	return iif_fences;
}

int gcip_fence_array_wait_signaler_submission(struct gcip_fence_array *fence_array,
					      unsigned int eventfd, int *remaining_signalers)
{
	return gcip_fence_wait_signaler_submission(fence_array->fences, fence_array->size, eventfd,
						   remaining_signalers);
}
