// SPDX-License-Identifier: GPL-2.0-only
/*
 * The inter-IP fence.
 *
 * The actual functionality (waiting and signaling) won't be done by the kernel driver. The main
 * role of it is creating fences with assigning fence IDs, initializing the fence table and managing
 * the life cycle of them.
 *
 * Copyright (C) 2023-2024 Google LLC
 */

#define pr_fmt(fmt) "iif: " fmt

#include <linux/atomic.h>
#include <linux/container_of.h>
#include <linux/export.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/idr.h>
#include <linux/kref.h>
#include <linux/lockdep.h>
#include <linux/lockdep_types.h>
#include <linux/sort.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/version.h>

#include <iif/iif-fence-table.h>
#include <iif/iif-fence.h>
#include <iif/iif-manager.h>
#include <iif/iif-shared.h>
#include <iif/iif-sync-file.h>

/* A compare function to sort fences by their ID. */
static int compare_iif_fence_by_id(const void *lhs, const void *rhs)
{
	const struct iif_fence *lfence = *(const struct iif_fence **)lhs;
	const struct iif_fence *rfence = *(const struct iif_fence **)rhs;

	if (lfence->id < rfence->id)
		return -1;
	if (lfence->id > rfence->id)
		return 1;
	return 0;
}

/*
 * Sorts fences by their ID.
 *
 * If developers are going to hold locks of multiple fences at the same time, they should sort them
 * using this function to prevent a potential dead lock.
 */
static inline void iif_fences_sort_by_id(struct iif_fence **fences, int size)
{
	sort(fences, size, sizeof(*fences), &compare_iif_fence_by_id, NULL);
}

/*
 * Holds the spin locks which protect the number of signalers of each fence in @fences without
 * saving the IRQ state.
 *
 * To prevent a deadlock, the caller should sort @fences using the `iif_fences_sort_by_id` function
 * first.
 *
 * The caller must use the `iif_fences_signalers_unlock` function to release the locks.
 */
static void iif_fences_signalers_lock(struct iif_fence **fences, int num_fences)
{
	int i;

	if (!fences || !num_fences)
		return;

	for (i = 0; i < num_fences; i++)
		spin_lock(&fences[i]->signalers_lock);
}

/*
 * Releases the spin locks held by the `iif_fences_signalers_lock` function without restoring the
 * IRQ state.
 */
static void iif_fences_signalers_unlock(struct iif_fence **fences, int num_fences)
{
	int i;

	if (!fences || !num_fences)
		return;

	for (i = num_fences - 1; i >= 0; i--)
		spin_unlock(&fences[i]->signalers_lock);
}

/*
 * Returns the number of remaining signalers to be submitted. Returns 0 if all signalers are
 * submitted.
 */
static int iif_fence_unsubmitted_signalers_locked(struct iif_fence *fence)
{
	lockdep_assert_held(&fence->signalers_lock);

	return fence->total_signalers - fence->submitted_signalers;
}

/*
 * Returns the number of outstanding signalers which have submitted signaler commands, but haven't
 * signaled @fence yet.
 */
static int iif_fence_outstanding_signalers_locked(struct iif_fence *fence)
{
	lockdep_assert_held(&fence->signalers_lock);

	return fence->submitted_signalers - fence->signaled_signalers;
}

/* Checks whether all signalers have signaled @fence or not. */
static bool iif_fence_is_signaled_locked(struct iif_fence *fence)
{
	lockdep_assert_held(&fence->signalers_lock);

	return fence->signaled_signalers == fence->total_signalers;
}

static inline bool iif_fence_has_retired(struct iif_fence *fence)
{
	return fence->state == IIF_FENCE_STATE_RETIRED;
}

/* Prints a warning log when @fence is retiring when there are remaining outstand waiters. */
static void iif_fence_retire_print_outstanding_waiters_warning(struct iif_fence *fence)
{
	char waiters[64] = { 0 };
	int i = 0, written = 0, tmp;
	enum iif_ip_type waiter;

	for_each_waiting_ip(&fence->mgr->fence_table, fence->id, waiter, tmp) {
		written += scnprintf(waiters + written, sizeof(waiters) - written, "%.*s%d", i, " ",
				     waiter);
		i++;
	}

	pr_warn("Fence is retiring when outstanding waiters > 0, it's likely a bug of the waiter IP driver, id=%d, waiter_ips=[%s]",
		fence->id, waiters);
}

/* Returns the fence ID to the ID pool. */
static void iif_fence_retire(struct iif_fence *fence)
{
	if (iif_fence_has_retired(fence))
		return;

	/*
	 * If the waiter IP driver calls `iif_fence_put` before it waits on waiter commands and
	 * calls `iif_fence_waited` somehow, the case that @fence retires while it is destroying
	 * can happen.
	 *
	 * In this case, there is a potential bug that the IP accesses @fence which is already
	 * retired. The waiter IP driver should ensure that calling `iif_fence_waited` first and
	 * then `iif_fence_put` in any case to guarantee that water IPs are not referring @fence
	 * anymore.
	 */
	if (fence->outstanding_waiters)
		iif_fence_retire_print_outstanding_waiters_warning(fence);

	ida_free(&fence->mgr->idp, fence->id);
	fence->state = IIF_FENCE_STATE_RETIRED;
}

/*
 * If there are no more outstanding waiters and no file binding to this fence, we can assume that
 * there will be no more signalers/waiters. Therefore, we can retire the fence ID earlier to not
 * block allocating an another fence.
 *
 * To prevent a deadlock, the caller should hold @fence->signalers_lock first and then
 * hold @fence->waiters_lock.
 */
static void iif_fence_retire_if_possible_locked(struct iif_fence *fence)
{
	lockdep_assert_held(&fence->signalers_lock);
	lockdep_assert_held(&fence->waiters_lock);

	if (!fence->outstanding_waiters && !iif_fence_outstanding_signalers_locked(fence) &&
	    !atomic_read(&fence->num_sync_file))
		iif_fence_retire(fence);
}

/*
 * Submits a signaler to @fence.
 *
 * If @complete is true, it will make @fence have finished the signaler submission. This must be
 * used only when @fence is going to be released before the signaler submission is being finished
 * and let the IP driver side notice that there was some problem by triggering registered callbacks.
 */
static int iif_fence_submit_signaler_with_complete_locked(struct iif_fence *fence, bool complete)
{
	struct iif_fence_all_signaler_submitted_cb *cur, *tmp;

	lockdep_assert_held(&fence->signalers_lock);

	/* Already all signalers are submitted. No more submission is allowed. */
	if (fence->submitted_signalers >= fence->total_signalers)
		return -EPERM;

	if (!complete)
		fence->submitted_signalers++;
	else
		fence->submitted_signalers = fence->total_signalers;

	/* The last signaler has been submitted. */
	if (!iif_fence_unsubmitted_signalers_locked(fence)) {
		list_for_each_entry_safe(cur, tmp, &fence->all_signaler_submitted_cb_list, node) {
			list_del_init(&cur->node);
			cur->func(fence, cur);
		}
	}

	return 0;
}

/*
 * Signals @fence.
 *
 * If @complete is true, it will make @fence have been signaled completely. This must be used only
 * when @fence is going to be released before it is signaled and let the waiter IP drivers notice
 * that there was some problem by triggering registered poll callbacks.
 *
 * The function returns the number of remaining signals to unblock the fence.
 *
 * If the function returns 0, it means that the fence has been unblocked and the caller is expected
 * to call the `iif_fence_notify_poll_cb` function to notify all others waiting on the fence.
 */
static int iif_fence_signal_with_complete_locked(struct iif_fence *fence, bool complete)
{
	int remaining_signals;

	lockdep_assert_held(&fence->signalers_lock);

	if (iif_fence_is_signaled_locked(fence))
		return 0;

	if (!complete)
		fence->signaled_signalers++;
	else
		fence->signaled_signalers = fence->total_signalers;

	remaining_signals = fence->total_signalers - fence->signaled_signalers;

	/*
	 * This function can be called when @fence is destroying, but unsignaled. In this case, the
	 * fence would be already retired theoretically and the fence table shouldn't be updated
	 * even though @fence->propagate is true.
	 */
	if (fence->propagate && !iif_fence_has_retired(fence))
		iif_fence_table_set_remaining_signals(&fence->mgr->fence_table, fence->id,
						      remaining_signals);

	return remaining_signals;
}

/*
 * Notifies the poll callbacks registered to @fence.
 *
 * This function must be called only if @fence is unblocked so that @fence->signalers_lock
 * doesn't have to be held.
 */
static void iif_fence_notify_poll_cb(struct iif_fence *fence)
{
	struct iif_fence_poll_cb *cur, *tmp;

	list_for_each_entry_safe(cur, tmp, &fence->poll_cb_list, node) {
		list_del_init(&cur->node);
		cur->func(fence, cur);
	}
}

/* Sets @fence->signal_error. */
static void iif_fence_set_signal_error_locked(struct iif_fence *fence, int error)
{
	lockdep_assert_held(&fence->signalers_lock);

	if (!error)
		return;

	if (iif_fence_is_signaled_locked(fence))
		pr_warn("The fence signal error is set after the fence is signaled");

	if (fence->signal_error)
		pr_warn("The fence signal error has been overwritten: %d -> %d",
			fence->signal_error, error);

	fence->signal_error = error;

	/*
	 * This function can be called when @fence is destroying, but unsignaled. In this case, the
	 * fence would be already retired theoretically and the fence table shouldn't be updated
	 * even though @fence->propagate is true.
	 */
	if (fence->propagate && !iif_fence_has_retired(fence))
		iif_fence_table_set_flag(&fence->mgr->fence_table, fence->id,
					 BIT(IIF_FLAG_ERROR_BIT));
}

/* Cleans up @fence which was initialized by the `iif_fence_init` function. */
static void iif_fence_do_destroy(struct iif_fence *fence)
{
	/*
	 * Theoretically, the work should be already finished since the meaning of this function
	 * called is that the refcount of @fence becomes 0. Nevertheless, cancel it just in case.
	 */
	cancel_work_sync(&fence->signaled_work);
	cancel_work_sync(&fence->waited_work);

	/* Checks whether there is remaining all_signaler_submitted and poll callbacks. */
	spin_lock(&fence->signalers_lock);

	if (!list_empty(&fence->all_signaler_submitted_cb_list) &&
	    fence->submitted_signalers < fence->total_signalers) {
		fence->all_signaler_submitted_error = -EDEADLK;
		iif_fence_submit_signaler_with_complete_locked(fence, true);
	}

	if (!list_empty(&fence->poll_cb_list) && !iif_fence_is_signaled_locked(fence)) {
		/*
		 * This case can happen when:
		 * - The signaler runtime just didn't submit enough signaler commands or it
		 *   becomes unavailable to submit commands in the middle (e.g., IP crashes).
		 * - The signaler IP kernel driver didn't call `iif_fence_signal{_with_status}`
		 *   before calling `iif_fence_put` somehow.
		 */
		pr_warn("Fence is destroying before signaled, likely a bug of the signaler, id=%d, signaler_ip=%d",
			fence->id, fence->signaler_ip);
		iif_fence_set_signal_error_locked(fence, -EDEADLK);
		iif_fence_signal_with_complete_locked(fence, true);
	}

	spin_unlock(&fence->signalers_lock);

	/*
	 * It is always safe to call this function.
	 * - If the if-clause above was executed, it means that the fence has been unblocked and it
	 *   is good to call this function.
	 * - If @fence->poll_cb_list was empty, this function call will be NO-OP.
	 * - If `iif_fence_is_signaled_locked(fence)` was true, it means that the fence was already
	 *   unblocked and it is good to call it. (In this case, all callbacks should be called when
	 *   the fence was unblocked and @fence->poll_cb_list should be already empty. It means that
	 *   the function call will be NO-OP theoretically.)
	 */
	iif_fence_notify_poll_cb(fence);

	/*
	 * It is supposed to be retired when the file is closed and there are no more outstanding
	 * waiters. However, let's ensure that the fence is retired before releasing it. We don't
	 * have to hold @fence->waiters_lock here because this function is called only when the
	 * fence can't be accessed anymore.
	 */
	iif_fence_retire(fence);

#if IS_ENABLED(CONFIG_DEBUG_SPINLOCK)
	lockdep_unregister_key(&fence->signalers_key);
#endif /* IS_ENABLED(CONFIG_DEBUG_SPINLOCK) */

	if (fence->ops && fence->ops->on_release)
		fence->ops->on_release(fence);
}

/* Will be called once the refcount of @fence becomes 0 and destroy it. */
static void iif_fence_destroy(struct kref *kref)
{
	struct iif_fence *fence = container_of(kref, struct iif_fence, kref);

	iif_fence_do_destroy(fence);
}

/* Will be called once the refcount of @fence becomes 0 and destroy it asynchronously. */
static void iif_fence_destroy_async(struct kref *kref)
{
	struct iif_fence *fence = container_of(kref, struct iif_fence, kref);

	schedule_work(&fence->put_work);
}

/*
 * This callback will be registered to @fence when the fence is initialized. It will be called when
 * @fence has been unblocked.
 */
static void iif_fence_unblocked_callback(struct iif_fence *fence, struct iif_fence_poll_cb *cb)
{
	iif_manager_broadcast_fence_unblocked(fence->mgr, fence);
}

/* A worker function which will be called when @fence is signaled. */
static void iif_fence_signaled_work_func(struct work_struct *work)
{
	struct iif_fence *fence = container_of(work, struct iif_fence, signaled_work);

	/*
	 * If @fence has been unblocked, it is safe to execute all registered poll callbacks
	 * without holding @fence->signaled_signalers_lock since the drivers can't register
	 * callbacks anymore.
	 */
	iif_fence_notify_poll_cb(fence);
}

static void iif_fence_waited_work_func(struct work_struct *work)
{
	/* TODO(b/330929140): release block wakelock of waiter IPs. */
}

static void iif_fence_put_work_func(struct work_struct *work)
{
	struct iif_fence *fence = container_of(work, struct iif_fence, put_work);

	iif_fence_do_destroy(fence);
}

int iif_fence_init(struct iif_manager *mgr, struct iif_fence *fence,
		   const struct iif_fence_ops *ops, enum iif_ip_type signaler_ip,
		   uint16_t total_signalers)
{
	unsigned int id_min = signaler_ip * IIF_NUM_FENCES_PER_IP;
	unsigned int id_max = id_min + IIF_NUM_FENCES_PER_IP - 1;

	fence->id = ida_alloc_range(&mgr->idp, id_min, id_max, GFP_KERNEL);
	if (fence->id < 0)
		return fence->id;

	fence->mgr = mgr;
	fence->signaler_ip = signaler_ip;
	fence->total_signalers = total_signalers;
	fence->submitted_signalers = 0;
	fence->signaled_signalers = 0;
	fence->outstanding_waiters = 0;
	fence->signal_error = 0;
	fence->ops = ops;
	fence->state = IIF_FENCE_STATE_INITIALIZED;
	fence->propagate = false;
	kref_init(&fence->kref);
#if IS_ENABLED(CONFIG_DEBUG_SPINLOCK)
	lockdep_register_key(&fence->signalers_key);
	__raw_spin_lock_init(spinlock_check(&fence->signalers_lock), "&fence->signalers_lock",
			     &fence->signalers_key, LD_WAIT_CONFIG);
#else
	spin_lock_init(&fence->signalers_lock);
#endif /* IS_ENABLED(CONFIG_DEBUG_SPINLOCK) */
	spin_lock_init(&fence->waiters_lock);
	iif_fence_table_init_fence_entry(&mgr->fence_table, fence->id, total_signalers);
	INIT_LIST_HEAD(&fence->poll_cb_list);
	INIT_LIST_HEAD(&fence->all_signaler_submitted_cb_list);
	atomic_set(&fence->num_sync_file, 0);
	INIT_WORK(&fence->signaled_work, &iif_fence_signaled_work_func);
	INIT_WORK(&fence->waited_work, &iif_fence_waited_work_func);
	INIT_WORK(&fence->put_work, &iif_fence_put_work_func);

	if (signaler_ip == IIF_IP_AP)
		fence->propagate = true;

	return iif_fence_add_poll_callback(fence, &fence->unblocked_cb,
					   iif_fence_unblocked_callback);
}

int iif_fence_install_fd(struct iif_fence *fence)
{
	struct iif_sync_file *sync_file;
	int fd;

	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0)
		return fd;

	sync_file = iif_sync_file_create(fence);
	if (IS_ERR(sync_file)) {
		put_unused_fd(fd);
		return PTR_ERR(sync_file);
	}

	fd_install(fd, sync_file->file);

	return fd;
}

void iif_fence_on_sync_file_release(struct iif_fence *fence)
{
	unsigned long signalers_flags, waiters_flags;

	spin_lock_irqsave(&fence->signalers_lock, signalers_flags);
	spin_lock_irqsave(&fence->waiters_lock, waiters_flags);

	iif_fence_retire_if_possible_locked(fence);

	spin_unlock_irqrestore(&fence->waiters_lock, waiters_flags);
	spin_unlock_irqrestore(&fence->signalers_lock, signalers_flags);
}

struct iif_fence *iif_fence_get(struct iif_fence *fence)
{
	if (fence)
		kref_get(&fence->kref);
	return fence;
}

struct iif_fence *iif_fence_fdget(int fd)
{
	struct iif_sync_file *sync_file;
	struct iif_fence *fence;

	sync_file = iif_sync_file_fdget(fd);
	if (IS_ERR(sync_file))
		return ERR_CAST(sync_file);

	fence = iif_fence_get(sync_file->fence);

	/*
	 * Since `iif_sync_file_fdget` opens the file and increases the file refcount, put here as
	 * we don't need to access the file anymore in this function.
	 */
	fput(sync_file->file);

	return fence;
}

void iif_fence_put(struct iif_fence *fence)
{
	if (fence)
		kref_put(&fence->kref, iif_fence_destroy);
}

void iif_fence_put_async(struct iif_fence *fence)
{
	if (fence)
		kref_put(&fence->kref, iif_fence_destroy_async);
}

int iif_fence_submit_signaler(struct iif_fence *fence)
{
	int ret;

	might_sleep();

	spin_lock(&fence->signalers_lock);
	ret = iif_fence_submit_signaler_with_complete_locked(fence, false);
	spin_unlock(&fence->signalers_lock);

	return ret;
}

int iif_fence_submit_waiter(struct iif_fence *fence, enum iif_ip_type ip)
{
	int unsubmitted = iif_fence_unsubmitted_signalers(fence);
	int status = iif_fence_get_signal_status(fence);

	might_sleep();

	if (unsubmitted)
		return unsubmitted;

	/*
	 * If @fence was unblocked with an error, reject submitting waiters.
	 *
	 * We don't have hold a lock here since the status cannot be changed to other status once
	 * it has been set to a negative errno.
	 *
	 * Also, even when @status was 0 here, but @fence's status has been just updated to 1
	 * (unblocked normally) or a negative errno right after this, it is still fine. The meaning
	 * of the status has become non-zero is that the signaler IP or AP already updated the fence
	 * table to mark the fence unblock so that waiter IPs can notice that after this function.
	 * As the kernel drivers are exptected to submit its waiter command to its IP after calling
	 * this function, the IP will check the fence table when they receive the command and can
	 * notice the fence unblock.
	 *
	 * This logic is for rejecting the command in early stage if the fence has been unblocked
	 * with an error if possible before taking a longer travel to the IP side.
	 */
	if (status < 0)
		return -EPERM;

	spin_lock(&fence->waiters_lock);

	fence->outstanding_waiters++;
	iif_fence_table_set_waiting_ip(&fence->mgr->fence_table, fence->id, ip);

	spin_unlock(&fence->waiters_lock);

	return 0;
}

int iif_fence_submit_signaler_and_waiter(struct iif_fence **in_fences, int num_in_fences,
					 struct iif_fence **out_fences, int num_out_fences,
					 enum iif_ip_type waiter_ip)
{
	int i;

	might_sleep();

	iif_fences_sort_by_id(in_fences, num_in_fences);
	iif_fences_sort_by_id(out_fences, num_out_fences);

	iif_fences_signalers_lock(in_fences, num_in_fences);

	/*
	 * Checks whether we can submit a waiter to @in_fences.
	 * If there are unsubmitted signalers, the caller should retry submitting waiters later.
	 */
	for (i = 0; in_fences && i < num_in_fences; i++) {
		if (iif_fence_unsubmitted_signalers_locked(in_fences[i])) {
			iif_fences_signalers_unlock(in_fences, num_in_fences);
			return -EAGAIN;
		}
	}

	/*
	 * We can release the lock of @in_fences because once they are able to submit a waiter, it
	 * means that all signalers have been submitted to @in_fences and the fact won't be changed.
	 * Will submit a waiter to @in_fences if @out_fences are able to submit a signaler.
	 */
	iif_fences_signalers_unlock(in_fences, num_in_fences);
	iif_fences_signalers_lock(out_fences, num_out_fences);

	/*
	 * Checks whether we can submit a signaler to @out_fences.
	 * If all signalers are already submitted, submitting signalers is not allowed anymore.
	 */
	for (i = 0; out_fences && i < num_out_fences; i++) {
		if (!iif_fence_unsubmitted_signalers_locked(out_fences[i])) {
			iif_fences_signalers_unlock(out_fences, num_out_fences);
			return -EPERM;
		}
	}

	/* Submits a signaler to @out_fences. */
	for (i = 0; out_fences && i < num_out_fences; i++)
		iif_fence_submit_signaler_with_complete_locked(out_fences[i], false);

	iif_fences_signalers_unlock(out_fences, num_out_fences);

	/* Submits a waiter to @in_fences. */
	for (i = 0; in_fences && i < num_in_fences; i++)
		iif_fence_submit_waiter(in_fences[i], waiter_ip);

	return 0;
}

int iif_fence_signal(struct iif_fence *fence)
{
	return iif_fence_signal_with_status(fence, 0);
}

int iif_fence_signal_async(struct iif_fence *fence)
{
	return iif_fence_signal_with_status_async(fence, 0);
}

int iif_fence_signal_with_status(struct iif_fence *fence, int error)
{
	int ret;

	ret = iif_fence_signal_with_status_async(fence, error);
	flush_work(&fence->signaled_work);

	return ret;
}

int iif_fence_signal_with_status_async(struct iif_fence *fence, int error)
{
	unsigned long signalers_flags, waiters_flags;
	int remaining_signals, ret;
	u8 fence_flag;

	/*
	 * The meaning of @fence->propagate is true when the signaler is an IP is that the IP has
	 * become faulty and the IIF driver takes care of updating the fence table. However, since
	 * the timing of the IP crash is nondeterministic, a race condition that the IP already
	 * unblocked the fence right before the crash, but the IP driver is going to signal the
	 * fence with an error because of the IP crash can happen. Therefore if the fence is already
	 * unblocked without error, we should ignore the signal error sent from the IP driver side.
	 *
	 * Note that if this case happens, some waiter IPs might be already notified of the fence
	 * unblock from the signaler IP before it crashes, but the IIF driver will notify waiter IP
	 * drivers and they may notify their IP of the unblock of the same fences again. That says
	 * waiter IPs can receive the fence unblock notification for the same fence for two times by
	 * the race condition, but we expect that they will ignore the second one.
	 *
	 * When the signaler is AP, that race condition won't happen since the fence table should be
	 * always managed by the IIF driver only and theoretically this logic won't have any effect.
	 */
	if (fence->propagate) {
		remaining_signals =
			iif_fence_table_get_remaining_signals(&fence->mgr->fence_table, fence->id);
		fence_flag = iif_fence_table_get_flag(&fence->mgr->fence_table, fence->id);

		if (!remaining_signals && !(fence_flag & BIT(IIF_FLAG_ERROR_BIT)) && error) {
			error = 0;
		} else if (!remaining_signals && (fence_flag & BIT(IIF_FLAG_ERROR_BIT)) && !error) {
			/*
			 * Theoretically, this case wouldn't happen since @fence->propagate was set
			 * means that the signaler IP has been crashed and the IP driver will signal
			 * the fence with an error. Handle it just in case and we can consider that
			 * the signaler command has been canceled.
			 */
			error = -ECANCELED;
		}
	}

	spin_lock_irqsave(&fence->signalers_lock, signalers_flags);

	if (iif_fence_is_signaled_locked(fence)) {
		pr_err("The fence is already signaled, id=%u", fence->id);
		ret = -EBUSY;
		goto out;
	}

	if (!iif_fence_outstanding_signalers_locked(fence)) {
		pr_err("There is no outstanding signalers, id=%u", fence->id);
		ret = -EPERM;
		goto out;
	}

	/*
	 * We should set the error before signaling the fence. Otherwise, if @fence->propagate is
	 * true so that the IIF driver is updating the fence table and if it signals the fence
	 * first, waiter IPs may misundestand that the fence has been unblocked without an error.
	 */
	iif_fence_set_signal_error_locked(fence, error);
	ret = iif_fence_signal_with_complete_locked(fence, false);

	/* We should hold both signalers and waiters lock to retire @fence. */
	spin_lock_irqsave(&fence->waiters_lock, waiters_flags);

	/*
	 * Normally @fence won't be retired here and it will be retired when there are no more
	 * outstanding waiters and all file descriptors linked to @fence are closed. However, if
	 * somehow all runtime and waiter IPs are crashed at the same time (or even the signaler IP
	 * is also crashed), the fence can be retired at this moment.
	 */
	iif_fence_retire_if_possible_locked(fence);

	spin_unlock_irqrestore(&fence->waiters_lock, waiters_flags);
out:
	spin_unlock_irqrestore(&fence->signalers_lock, signalers_flags);

	if (!ret)
		schedule_work(&fence->signaled_work);

	return ret;
}

int iif_fence_get_signal_status(struct iif_fence *fence)
{
	unsigned long flags;
	int status = 0;

	spin_lock_irqsave(&fence->signalers_lock, flags);

	if (iif_fence_is_signaled_locked(fence))
		status = fence->signal_error ?: 1;

	spin_unlock_irqrestore(&fence->signalers_lock, flags);

	return status;
}

void iif_fence_set_propagate_unblock(struct iif_fence *fence)
{
	/*
	 * It is safe to not hold any locks because this function is expected to be called before
	 * signaling @fence and @fence->propagate will be accessed only when the fence has been
	 * unblocked and the poll callbacks are executed. The value won't be changed while the
	 * callbacks are being processed.
	 */
	fence->propagate = true;
}

bool iif_fence_is_signaled(struct iif_fence *fence)
{
	unsigned long flags;
	bool signaled;

	spin_lock_irqsave(&fence->signalers_lock, flags);
	signaled = iif_fence_is_signaled_locked(fence);
	spin_unlock_irqrestore(&fence->signalers_lock, flags);

	return signaled;
}

void iif_fence_waited(struct iif_fence *fence, enum iif_ip_type ip)
{
	iif_fence_waited_async(fence, ip);
	flush_work(&fence->waited_work);
}

void iif_fence_waited_async(struct iif_fence *fence, enum iif_ip_type ip)
{
	unsigned long signalers_flags, waiters_flags;

	spin_lock_irqsave(&fence->signalers_lock, signalers_flags);
	spin_lock_irqsave(&fence->waiters_lock, waiters_flags);

	if (fence->outstanding_waiters) {
		fence->outstanding_waiters--;
		iif_fence_retire_if_possible_locked(fence);
	}

	spin_unlock_irqrestore(&fence->waiters_lock, waiters_flags);
	spin_unlock_irqrestore(&fence->signalers_lock, signalers_flags);

	/* TODO(b/330929140): trigger @fence->waited_work to release block wakelock of @ip. */
}

int iif_fence_add_poll_callback(struct iif_fence *fence, struct iif_fence_poll_cb *poll_cb,
				iif_fence_poll_cb_t func)
{
	unsigned long flags;
	int ret = 0;

	spin_lock_irqsave(&fence->signalers_lock, flags);

	if (iif_fence_is_signaled_locked(fence)) {
		INIT_LIST_HEAD(&poll_cb->node);
		ret = -EPERM;
		goto out;
	}

	poll_cb->func = func;
	list_add_tail(&poll_cb->node, &fence->poll_cb_list);
out:
	spin_unlock_irqrestore(&fence->signalers_lock, flags);

	return ret;
}

bool iif_fence_remove_poll_callback(struct iif_fence *fence, struct iif_fence_poll_cb *poll_cb)
{
	unsigned long flags;
	bool removed = false;

	spin_lock_irqsave(&fence->signalers_lock, flags);

	if (!list_empty(&poll_cb->node)) {
		list_del_init(&poll_cb->node);
		removed = true;
	}

	spin_unlock_irqrestore(&fence->signalers_lock, flags);

	return removed;
}

int iif_fence_add_all_signaler_submitted_callback(struct iif_fence *fence,
						  struct iif_fence_all_signaler_submitted_cb *cb,
						  iif_fence_all_signaler_submitted_cb_t func)
{
	int ret = 0;
	unsigned long flags;

	spin_lock_irqsave(&fence->signalers_lock, flags);

	cb->remaining_signalers = iif_fence_unsubmitted_signalers_locked(fence);

	/* Already all signalers are submitted. */
	if (!cb->remaining_signalers) {
		ret = -EPERM;
		goto out;
	}

	cb->func = func;
	list_add_tail(&cb->node, &fence->all_signaler_submitted_cb_list);
out:
	spin_unlock_irqrestore(&fence->signalers_lock, flags);

	return ret;
}

bool iif_fence_remove_all_signaler_submitted_callback(
	struct iif_fence *fence, struct iif_fence_all_signaler_submitted_cb *cb)
{
	bool removed = false;
	unsigned long flags;

	spin_lock_irqsave(&fence->signalers_lock, flags);

	if (!list_empty(&cb->node)) {
		list_del_init(&cb->node);
		removed = true;
	}

	spin_unlock_irqrestore(&fence->signalers_lock, flags);

	return removed;
}

int iif_fence_unsubmitted_signalers(struct iif_fence *fence)
{
	unsigned long flags;
	int unsubmitted;

	spin_lock_irqsave(&fence->signalers_lock, flags);
	unsubmitted = iif_fence_unsubmitted_signalers_locked(fence);
	spin_unlock_irqrestore(&fence->signalers_lock, flags);

	return unsubmitted;
}

int iif_fence_submitted_signalers(struct iif_fence *fence)
{
	return fence->total_signalers - iif_fence_unsubmitted_signalers(fence);
}

int iif_fence_signaled_signalers(struct iif_fence *fence)
{
	unsigned long flags;
	int signaled;

	spin_lock_irqsave(&fence->signalers_lock, flags);
	signaled = fence->signaled_signalers;
	spin_unlock_irqrestore(&fence->signalers_lock, flags);

	return signaled;
}

int iif_fence_outstanding_waiters(struct iif_fence *fence)
{
	unsigned long flags;
	int outstanding;

	spin_lock_irqsave(&fence->waiters_lock, flags);
	outstanding = fence->outstanding_waiters;
	spin_unlock_irqrestore(&fence->waiters_lock, flags);

	return outstanding;
}
