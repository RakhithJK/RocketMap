#!/usr/bin/python
# -*- coding: utf-8 -*-

import logging
import time

from collections import OrderedDict, deque
from datetime import datetime, timedelta
from requests import Session
from threading import Lock, Thread

from .account import AccountBanned, check_login, setup_api
from .altitude import get_altitude
from .models import Account, Token
from .utils import distance
from .transform import jitter_location

log = logging.getLogger(__name__)


class AccountManager(object):
    def __init__(self, args, db_queue, wh_queue, high_level=30):

        self.args = args
        self.dbq = db_queue
        self.whq = wh_queue
        self.key_scheduler = None
        self.high_level = high_level
        self.instance_id = args.instance_id

        self.replenish_count = {
            'scanner': args.workers,
            'high-level': args.hlvl_workers
        }

        self.allocated = {
            'scanner': set(),
            'high-level': set()
        }

        self.active = {
            'scanner': OrderedDict(),
            'high-level': OrderedDict(),
        }

        self.accounts = {
            'scanner': OrderedDict(),
            'high-level': OrderedDict(),
            'failed': deque(),
            'captcha': deque()
        }

        self.accounts_locks = {
            'scanner': Lock(),
            'high-level': Lock()
        }

    def run_manager(self):
        # Release accounts previously used by this instance.
        self._release_instance()
        # Load required accounts to start working.
        self._account_keeper()
        # Captcha solver current thread ID.
        self.thread_id = 0

        cycle = 0
        time.sleep(10)
        while True:
            cycle += 1

            # Run once every 15 seconds.
            self._account_keeper(notice=(cycle % 40 == 0))
            if self.args.captcha_solving:
                self._captcha_manager()

            # Run once every 60 seconds.
            if cycle % 4 == 0:
                self._account_recycler()

            # Run once every 10 min.
            if cycle % 40 == 0:
                self._account_monitor()
                cycle = 0

            time.sleep(15)

    def _account_keeper(self, notice=False):
        if notice:
            log.info('Account keeper running. ' +
                     'Managing %d scanner and %d high-level accounts.',
                     len(self.allocated['scanner']),
                     len(self.allocated['high-level']))

        self._replenish_accounts(False, notice)
        self._replenish_accounts(True, notice)

        self._release_accounts(False)
        self._release_accounts(True)

    def _replenish_accounts(self, hlvl, notice):
        if hlvl:
            account_pool = 'high-level'
            target_count = self.args.hlvl_workers
        else:
            account_pool = 'scanner'
            target_count = self.args.workers

        replenish_count = self.replenish_count[account_pool]

        if replenish_count <= 0 or target_count <= 0:
            return

        accounts_lock = self.accounts_locks[account_pool]
        allocated_pool = self.allocated[account_pool]
        spare_pool = self.accounts[account_pool]

        log.info('Fetching %d %s accounts from database.',
                 replenish_count, account_pool)
        accounts = self._fetch_accounts(replenish_count, hlvl)

        if not accounts and notice:
            log.warning('Insufficient %s accounts in database.', account_pool)
            return

        log.info('Loading %d %s accounts to spare account pool.',
                 len(accounts), account_pool)

        # Add allocated accounts to spare account pool.
        allocated_count = 0
        with accounts_lock:
            for username, account in accounts.iteritems():
                # Skip the account if it's already allocated.
                if username in allocated_pool:
                    continue
                allocated_count += 1
                # Add account to allocated account pool.
                allocated_pool.add(username)

                # Add account to spare account pool.
                account['allocated'] = True
                account['instance_id'] = self.instance_id
                account['last_modified'] = datetime.utcnow()
                spare_pool[username] = account

            self.replenish_count[account_pool] -= allocated_count

        failed_count = replenish_count - allocated_count
        if failed_count > 0:
            log.error('Failed to allocate %d %s accounts from database.',
                      failed_count, account_pool)

    # Check for excess accounts that can be deallocated.
    def _release_accounts(self, hlvl):
        if hlvl:
            account_pool = 'high-level'
            holding_time = self.args.hlvl_workers_holding_time
            target_count = self.args.hlvl_workers
        else:
            account_pool = 'scanner'
            holding_time = self.args.workers_holding_time
            target_count = self.args.workers

        accounts_lock = self.accounts_locks[account_pool]
        allocated_pool = self.allocated[account_pool]
        spare_pool = self.accounts[account_pool]

        excess_count = min(len(allocated_pool) - target_count,
                           len(spare_pool))

        if excess_count <= 0:
            return

        released_accounts = {}
        with accounts_lock:
            for username in spare_pool.keys():
                account = spare_pool[username]
                hold_time = (datetime.utcnow() -
                             account['last_modified']).total_seconds()
                if hold_time > holding_time:
                    # Release account from this instance.
                    account = spare_pool.pop(username)
                    account['allocated'] = False
                    allocated_pool.remove(username)
                    log.info('Deallocated %s account %s: idle for %d seconds.',
                             account_pool, username, hold_time)

                    released_accounts[username] = Account.db_format(account)
                    excess_count -= 1
                else:
                    # Don't need to check further, account pool is sorted.
                    break
                if excess_count == 0:
                    break

        if released_accounts:
            # Update account information in database.
            self.dbq.put((Account, released_accounts))
            log.debug('Released and deallocated %d excess %s accounts.',
                      len(released_accounts), account_pool)

    # Monitor failed accounts to check their status.
    def _account_recycler(self):
        now = datetime.utcnow()
        failed_count = len(self.accounts['failed'])
        log.debug('Account recycler running. Checking status of %d accounts.',
                  failed_count)

        # Define maximum ban level allowed to continue working.
        if not self.args.shadow_ban_scan:
            ban_level = AccountBanned.Clear
        else:
            ban_level = AccountBanned.Shadowban

        # Search through failed account pool for recyclable accounts.
        while failed_count > 0:
            account, reason, notified = self.accounts['failed'].popleft()
            failed_count -= 1

            rest_interval = self.args.account_rest_interval

            if 'exception' in reason:
                rest_interval = rest_interval * 0.1
            elif account['banned'] != AccountBanned.Clear:
                rest_interval = rest_interval * 10

            hold_time = (account['last_modified'] +
                         timedelta(seconds=rest_interval))

            if now < hold_time:
                if not notified:
                    time = (hold_time - now).total_seconds()
                    log.info('Account %s needs to stop (%s) for %.0f minutes.',
                             account['username'], reason, time/60)
                    notified = True

                self.accounts['failed'].append((account, reason, notified))
                continue

            if account['banned'] > ban_level:
                # Deallocate banned accounts.
                account_pool = account['account_pool']
                log.info('Released and deallocated banned account %s.',
                         account['username'])
                account['allocated'] = False
                self.allocated[account_pool].remove(account['username'])
            else:
                # Return account to the appropriate account pool.
                log.info('Returning account %s to spare account pool.',
                         account['username'])

                if account['level'] >= self.high_level:
                    account_pool = 'high-level'
                else:
                    account_pool = 'scanner'

                account['account_pool'] = account_pool
                spare_pool = self.accounts[account_pool]
                accounts_lock = self.accounts_locks[account_pool]

                with accounts_lock:
                    spare_pool[account['username']] = account
                    self.replenish_count[account_pool] -= 1

            # Update account information in database.
            account['fail'] = False
            self.dbq.put((Account, {0: Account.db_format(account)}))

    def _account_monitor(self):
        # Reset allocated accounts after one day.
        query = (Account
                 .update(allocated=False, fail=False)
                 .where((Account.last_modified <
                         (datetime.utcnow() - timedelta(days=1))))
                 .execute())
        log.debug('Reseted %d old allocated accounts.', query)

        # Reset warning after one week.
        query = (Account
                 .update(allocated=False, warning=False)
                 .where((Account.warning == 1) &
                        (Account.last_modified <
                         (datetime.utcnow() - timedelta(weeks=1))))
                 .execute())
        log.debug('Reseted warnings on %d accounts.', query)

        # Reset shadow banned accounts after two weeks.
        query = (Account
                 .update(allocated=False, banned=AccountBanned.Clear)
                 .where((Account.banned == AccountBanned.Shadowban) &
                        (Account.last_modified <
                         (datetime.utcnow() - timedelta(weeks=2))))
                 .execute())
        log.debug('Reseted %d shadow banned accounts.', query)

        # Reset temporarily banned accounts after six weeks.
        query = (Account
                 .update(allocated=False, banned=AccountBanned.Clear)
                 .where((Account.banned == AccountBanned.Temporary) &
                        (Account.last_modified <
                         (datetime.utcnow() - timedelta(weeks=6))))
                 .execute())
        log.debug('Reseted %d temporarily banned accounts.', query)

    # Clears all accounts in the database.
    def clear_all(self):
        query = Account.delete().execute()
        if query:
            log.info('Cleared %d accounts from the database.', query)

    # Filter account list and insert new accounts in the database.
    def insert_new(self, accounts):
        log.info('Processing %d accounts into the database.', len(accounts))
        step = 250
        count = 0
        for idx in range(0, len(accounts), step):
            accounts_batch = accounts[idx:idx+step]
            usernames = [a['username'] for a in accounts_batch]
            query = (Account
                     .select(Account.username)
                     .where(Account.username << usernames)
                     .dicts())

            db_usernames = [dbu['username'] for dbu in query]
            new_accounts = [x for x in accounts_batch
                            if x['username'] not in db_usernames]
            if not new_accounts:
                continue

            with Account.database().atomic():
                if Account.insert_many(new_accounts).execute():
                    count += len(new_accounts)

        log.info('Inserted %d new accounts into the database.', count)

    # Release accounts previously used by this instance.
    def _release_instance(self):
        query = (Account
                 .update(allocated=False, fail=False)
                 .where(Account.instance_id == self.instance_id))
        rows = query.execute()
        log.debug('Released %d accounts previously used by this instance.',
                  rows)

    # Allocate available accounts from the database.
    def _allocate_accounts(self, count, reuse, hlvl):
        conditions = ((Account.allocated == 0) & (Account.fail == 0))

        if self.args.no_pokemon or self.args.shadow_ban_scan:
            conditions &= (Account.banned <= AccountBanned.Shadowban)
        else:
            conditions &= (Account.banned == AccountBanned.Clear)
        if reuse:
            conditions &= (Account.instance_id == self.instance_id)
        else:
            conditions &= (Account.instance_id.is_null() |
                           (Account.instance_id != self.instance_id))
        if hlvl:
            conditions &= (Account.level >= self.high_level)
        elif not self.args.hlvl_scan:
            # Allow high-level accounts to be allocated to scanning.
            conditions &= (Account.level < self.high_level)

        accounts = {}
        try:
            query = (Account
                     .select()
                     .where(conditions)
                     .order_by(Account.last_modified.desc())
                     .limit(min(250, count))
                     .dicts())

            for dba in query:
                accounts[dba['username']] = dba

            if accounts:
                query = (Account
                         .update(allocated=True,
                                 instance_id=self.instance_id)
                         .where((Account.allocated == 0) &
                                (Account.username << accounts.keys())))
                allocated = query.execute()

                unallocated = len(accounts) - allocated
                if unallocated > 0:
                    log.error('Unable to allocate %d accounts.', unallocated)

        except Exception as e:
            log.exception('Error allocating accounts from database: %s', e)

        return accounts

    # Allocate and load accounts from the database.
    def _fetch_accounts(self, count, hlvl):
        accounts = {}
        if count > 0:
            accounts = self._allocate_accounts(count, True, hlvl)
            count -= len(accounts)
        if count > 0:
            accounts.update(self._allocate_accounts(count, False, hlvl))

        return accounts

    # Get next account that is ready to start working.
    def get_account(self, location=None, hlvl=False):
        if hlvl:
            account_pool = 'high-level'
            speed_limit = self.args.hlvl_kph
        else:
            account_pool = 'scanner'
            speed_limit = self.args.kph

        accounts_lock = self.accounts_locks[account_pool]
        allocated_pool = self.allocated[account_pool]
        active_pool = self.active[account_pool]
        spare_pool = self.accounts[account_pool]

        with accounts_lock:
            now = datetime.utcnow()
            picked_username = None
            last_scan_secs = 0

            # Loop through available spare accounts.
            # Reversed iteration to maximize account reusage.
            for username in reversed(spare_pool.keys()):
                account = spare_pool[username]

                # Check if this account remains below speed limit.
                if location and speed_limit and account['last_scan']:
                    last_scan_secs = (now -
                                      account['last_scan']).total_seconds()
                    old_location = (account['latitude'], account['longitude'])

                    meters = distance(old_location, location)
                    cooldown_time_secs = meters / speed_limit * 3.6

                    # Not enough time has passed for this one.
                    sleep_time = cooldown_time_secs - last_scan_secs
                    if sleep_time > 10:
                        continue

                # We've found an account ready to work.
                picked_username = username
                break

            if picked_username:
                picked_account = spare_pool.pop(picked_username)

                log.info('Picked account %s from %s account pool. ',
                         picked_username, account_pool)

                # Make sure account is not active.
                if picked_username not in active_pool:
                    picked_account['account_pool'] = account_pool
                    active_pool[picked_username] = picked_account

                    return picked_account

            elif hlvl and not self.args.hlvl_workers:
                working_count = (len(allocated_pool) -
                                 self.replenish_count[account_pool])
                if working_count >= self.args.hlvl_workers_max:
                    return None

                # "On-the-fly" high-level account allocation.
                accounts = self._fetch_accounts(1, hlvl=True)
                if len(accounts) > 0:
                    picked_username, picked_account = accounts.popitem()

                    # Add account to allocated account pool.
                    allocated_pool.add(picked_username)
                    picked_account['allocated'] = True
                    picked_account['instance_id'] = self.instance_id
                    log.info('Allocated "on-the-fly" high-level account: %s.',
                             picked_username)

                    picked_account['account_pool'] = account_pool
                    active_pool[picked_username] = picked_account

                    return picked_account

        return None

    # Move account from active to spare account pool.
    def release_account(self, account):
        username = account['username']
        account_pool = account['account_pool']
        active_pool = self.active[account_pool]

        # Make sure account is active.
        if username not in active_pool:
            log.error('Trying to release a %s account %s that is not active.',
                      account_pool, username)
            return

        accounts_lock = self.accounts_locks[account_pool]
        allocated_pool = self.allocated[account_pool]
        spare_pool = self.accounts[account_pool]

        if account_pool == 'scanner':
            holding_time = self.args.workers_holding_time
        else:
            holding_time = self.args.hlvl_workers_holding_time

        with accounts_lock:
            active_pool.pop(username)

            if holding_time > 0:
                # Keep account allocated to this instance for a while.
                log.info('Moving active %s account %s to spare account pool.',
                         account_pool, username)
                spare_pool[username] = account
            else:
                # Immediately release account from this instance.
                account['allocated'] = False
                allocated_pool.remove(username)
                log.info('Released and deallocated account %s.', username)

        # Update account information in database.
        self.dbq.put((Account, {0: Account.db_format(account)}))

    # Move account from active to failed account pool.
    def failed_account(self, account, reason):
        username = account['username']
        account_pool = account['account_pool']
        accounts_lock = self.accounts_locks[account_pool]
        active_pool = self.active[account_pool]

        # Make sure account is active.
        if username not in active_pool:
            log.error('Account %s failed but it was not active.', username)
        else:
            active_pool.pop(username)
            account['fail'] = True

            log.info('Moving active %s account %s to failed account pool.',
                     account_pool, username)

            if account['banned'] == AccountBanned.Shadowban:
                reason = 'Shadow banned'
            if account['banned'] == AccountBanned.Temporary:
                reason = 'Temporary ban'
            if account['banned'] == AccountBanned.Permanent:
                reason = 'Permanent ban'
            self.accounts['failed'].append((account, reason, False))

            with accounts_lock:
                self.replenish_count[account_pool] += 1

        # Update account information in database.
        self.dbq.put((Account, {0: Account.db_format(account)}))

    # Check account status and update the database.
    def check_account(self, account, status):
        username = account['username']
        account_pool = account['account_pool']
        active_pool = self.active[account_pool]

        # Check if account is still active.
        if username not in active_pool:
            status['message'] = (
                'Account {} was removed from active {} account pool. ' +
                'Switching accounts...').format(username, account_pool)
            return False

        # Check if account is shadow banned.
        if (not self.args.shadow_ban_scan and
                account['banned'] == AccountBanned.Shadowban):
            status['message'] = (
                'Account {} is shadow banned: {} scans without ' +
                'rare Pokemon. Switching accounts...').format(
                    account['username'], status['norares'])
            log.warning(status['message'])
            self.failed_account(account, 'shadowban')
            return False

        self.dbq.put((Account, {0: Account.db_format(account)}))
        return True

    # Check and handle captcha encounters.
    def handle_captcha(self, account, status, api, response):
        username = account['username']

        # Default result: no captcha, no failure.
        result = {'found': False, 'failed': False}

        if response and 'CHECK_CHALLENGE' not in response.get('responses', {}):
            return result

        captcha_url = response['responses']['CHECK_CHALLENGE'].challenge_url

        if len(captcha_url) < 2:
            return result

        # Update thread status if it belongs to this account.
        if status['username'] == account['username']:
            status['captcha'] += 1

        # Default result: captcha found, failed to solve it.
        result = {'found': False, 'failed': False}
        account['captcha'] = True

        # Captcha solving is disabled completely.
        if not self.args.captcha_solving:
            status['message'] = (
                'Account {} has encountered a captcha. ' +
                'Putting account away.').format(username)
            log.warning(status['message'])

            # Send webhook message.
            if 'captcha' in self.args.wh_types:
                wh_message = {
                    'status_name': self.args.status_name,
                    'status': 'encounter',
                    'mode': 'disabled',
                    'account': username,
                    'captcha': status['captcha'],
                    'time': 0
                }
                self.whq.put(('captcha', wh_message))

            # Put account out of circulation - handled by check_account().
            self.failed_account(account, 'captcha')

        # Automatic captcha solving only.
        elif self.args.captcha_key and self.args.manual_captcha_timeout == 0:
            if self._automatic_captcha_solve(account, status, api,
                                             captcha_url):
                # Solved the captcha on the spot, no fuzz.
                result['failed'] = False
                account['captcha'] = False
            else:
                status['message'] = (
                    'Account {} has encountered a captcha and failed to ' +
                    'solve it. Putting account away.').format(username)
                log.warning(status['message'])

                # Put account out of circulation - handled by check_account().
                self.failed_account(account, 'captcha failed')

        # Hybrid/Manual captcha solving.
        else:
            timeout = self.args.manual_captcha_timeout
            if self.args.captcha_key:
                solving_mode = 'hybrid'
                status['message'] = (
                    'Account {} has encountered a captcha. Hybrid-mode, ' +
                    'waiting {} secs for a token.').format(username, timeout)
            else:
                solving_mode = 'manual'
                status['message'] = (
                    'Account {} has encountered a captcha. Manual-mode, ' +
                    'waiting for a token.').format(username)

            log.warning(status['message'])

            if 'captcha' in self.args.wh_types:
                wh_message = {
                    'status_name': self.args.status_name,
                    'status': 'encounter',
                    'mode': solving_mode,
                    'account': username,
                    'captcha': status['captcha'],
                    'time': timeout
                }
                self.whq.put(('captcha', wh_message))

            # Put account out of circulation - handled by check_account().
            self._captcha_account(account, status, captcha_url)

        return result

    # Move account from active to captcha account pool.
    def _captcha_account(self, account, status, captcha_url):
        username = account['username']
        account_pool = account['account_pool']
        accounts_lock = self.accounts_locks[account_pool]
        active_pool = self.active[account_pool]

        # Make sure account is active.
        if username not in active_pool:
            log.error('Account %s has encountered a captcha but it was ' +
                      'not active.', username)
        else:
            active_pool.pop(username)
            account['fail'] = True

            log.info('Moving active %s account %s to captcha account pool.',
                     account_pool, username)

            self.accounts['captcha'].append((account, status, captcha_url))

            with accounts_lock:
                self.replenish_count[account_pool] += 1

        # Update account information in database.
        self.dbq.put((Account, {0: Account.db_format(account)}))

    # Returns true if captcha was succesfully solved.
    def _automatic_captcha_solve(self, account, status, api, captcha_url):
        status['message'] = (
            'Account {} is encountering a captcha, starting 2captcha ' +
            'sequence.').format(account['username'])
        log.warning(status['message'])

        if 'captcha' in self.args.wh_types:
            wh_message = {
                'status_name': self.args.status_name,
                'status': 'encounter',
                'mode': '2captcha',
                'account': account['username'],
                'captcha': status['captcha'],
                'time': 0}
            self.whq.put(('captcha', wh_message))

        time_start = time.time()
        captcha_token = token_request(self.args, status, captcha_url)
        time_elapsed = time.time() - time_start

        if 'ERROR' in captcha_token:
            log.warning('Unable to resolve captcha, please check your ' +
                        '2captcha API key and/or wallet balance.')
            if 'captcha' in self.args.wh_types:
                wh_message['status'] = 'error'
                wh_message['time'] = time_elapsed
                self.whq.put(('captcha', wh_message))

            return False
        else:
            status['message'] = (
                'Retrieved captcha token, attempting to verify challenge ' +
                'for {}.').format(account['username'])
            log.info(status['message'])

            req = api.create_request()
            req.verify_challenge(token=captcha_token)
            response = req.call(False)
            time_elapsed = time.time() - time_start
            success = response['responses']['VERIFY_CHALLENGE'].success
            if success:
                status['message'] = (
                    'Account {} got its captcha solved.').format(
                    account['username'])
            else:
                status['message'] = (
                    'Account {} failed to verify challenge, putting it ' +
                    'away for now.').format(account['username'])
            log.info(status['message'])
            if 'captcha' in self.args.wh_types:
                wh_message['status'] = 'success' if success else 'failure'
                wh_message['time'] = time_elapsed
                self.whq.put(('captcha', wh_message))

            return success

    # Keeps track of captcha'd accounts awaiting for manual token inputs.
    def _captcha_manager(self):
        tokens_needed = len(self.accounts['captcha'])
        if tokens_needed > 0:
            tokens = Token.get_valid(tokens_needed)
            tokens_available = len(tokens)
            solvers = min(tokens_needed, tokens_available)
            log.debug('Captcha manager running. Captchas: %d - Tokens: %d',
                      tokens_needed, tokens_available)
            for i in range(0, solvers):
                hash_key = self.key_scheduler.next()

                t = Thread(
                    target=self._captcha_solver,
                    name='captcha-solver-{}'.format(self.thread_id),
                    args=(hash_key, tokens[i]))
                t.daemon = True
                t.start()

                self.thread_id += 1
                if self.thread_id > 999:
                    self.thread_id = 0
                # Wait a bit before launching next thread.
                time.sleep(1)

            # Hybrid mode - after waiting send to automatic captcha solver.
            if self.args.captcha_key and self.args.manual_captcha_timeout > 0:
                tokens_remaining = tokens_needed - tokens_available
                # Safety guard, don't grab too much work.
                tokens_remaining = min(tokens_remaining, 5)
                for i in range(0, tokens_remaining):
                    account = self.accounts['captcha'][0][0]
                    hold_time = (datetime.utcnow() -
                                 account['last_modified']).total_seconds()
                    if hold_time > self.args.manual_captcha_timeout:
                        log.debug('Account %s waited %ds for captcha token ' +
                                  'and reached the %ds timeout.',
                                  account['username'], hold_time,
                                  self.args.manual_captcha_timeout)
                        hash_key = self.key_scheduler.next()

                        t = Thread(
                            target=self._captcha_solver,
                            name='captcha-solver-{}'.format(self.thread_id),
                            args=hash_key)
                        t.daemon = True
                        t.start()

                        self.thread_id += 1
                        if self.thread_id > 999:
                            self.thread_id = 0

                        # Wait a little bit before launching next thread.
                        time.sleep(1)
                    else:
                        break

    # Log-in with account, setup API and attempt to solve captcha with token.
    def _captcha_solver(self, hash_key, token=None):
        account, status, captcha_url = self.accounts['captcha'].popleft()

        username = account['username']
        if username != status['username']:
            # Search worker thread has moved on, don't use its status.
            status = {
                'message': '',
                'captcha': 1,
                'proxy_display': 'No',
                'proxy_url': False
            }

        status['message'] = 'Waking up account {} to solve captcha.'.format(
                            username)
        log.info(status['message'])

        api = setup_api(self.args, status, account)

        if hash_key:
            log.debug('Using hash key %s to solve this captcha.', hash_key)
            api.activate_hash_server(hash_key)

        location = (account['latitude'], account['longitude'])
        altitude = get_altitude(self.args, location)
        location = (location[0], location[1], altitude)

        if self.args.jitter:
            # Jitter location before attempting to verify challenge.
            location = jitter_location(location)

        api.set_position(*location)
        check_login(self.args, account, api, status['proxy_url'])

        if not token:
            token = token_request(self.args, status, captcha_url)

        req = api.create_request()
        req.verify_challenge(token=token)
        response = req.call(False)
        success = response['responses']['VERIFY_CHALLENGE'].success

        if success:
            status['message'] = (
                'Account {} successfully solved its captcha, ' +
                'returning to active duty.').format(username)
            log.info(status['message'])

            # Update account information in database.
            account['captcha'] = False
            self.dbq.put((Account, {0: Account.db_format(account)}))

            # Return account to the appropriate account pool.
            account_pool = account['account_pool']
            accounts_lock = self.accounts_locks[account_pool]
            with accounts_lock:
                self.accounts[account_pool][username] = account
                self.replenish_count[account_pool] -= 1

        else:
            status['message'] = (
                'Account {} failed to verify challenge, putting it back ' +
                'in captcha account pool.').format(username)
            log.warning(status['message'])
            self.accounts['captcha'].append((status, account, captcha_url))

        if 'captcha' in self.args.wh_types:
            hold_time = (datetime.utcnow() -
                         account['last_modified']).total_seconds()
            wh_message = {
                'status_name': self.args.status_name,
                'mode': 'manual' if token else '2captcha',
                'account': 'scanner',
                'captcha': status['captcha'],
                'time': int(hold_time),
                'status': 'success' if success else 'failure'
            }
            self.whq.put(('captcha', wh_message))

        # Let things settle down a bit.
        time.sleep(1)


def token_request(args, status, url):
    s = Session()
    # Fetch the CAPTCHA_ID from 2captcha.
    try:
        request_url = (
            'http://2captcha.com/in.php?key={}&method=userrecaptcha' +
            '&googlekey={}&pageurl={}').format(args.captcha_key,
                                               args.captcha_dsk, url)
        captcha_id = s.post(request_url, timeout=5).text.split('|')[1]
        captcha_id = str(captcha_id)
    # IndexError implies that the retuned response was a 2captcha error.
    except IndexError:
        return 'ERROR'
    status['message'] = (
        'Retrieved captcha ID: {}; now retrieving token.').format(captcha_id)
    log.info(status['message'])
    # Get the response, retry every 5 seconds if it's not ready.
    recaptcha_response = s.get(
        'http://2captcha.com/res.php?key={}&action=get&id={}'.format(
            args.captcha_key, captcha_id), timeout=5).text
    while 'CAPCHA_NOT_READY' in recaptcha_response:
        log.info('Captcha token is not ready, retrying in 5 seconds...')
        time.sleep(5)
        recaptcha_response = s.get(
            'http://2captcha.com/res.php?key={}&action=get&id={}'.format(
                args.captcha_key, captcha_id), timeout=5).text
    token = str(recaptcha_response.split('|')[1])
    return token
