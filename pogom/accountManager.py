#!/usr/bin/python
# -*- coding: utf-8 -*-

import logging
import time

from collections import OrderedDict, deque
from datetime import datetime, timedelta
from requests import Session
from threading import Lock, Thread

from .account import AccountBanned, check_login
from .altitude import get_altitude
from .models import Account, Token
from .proxy import get_new_proxy
from .utils import distance
from .transform import jitter_location

from pgoapi import PGoApi
from .fakePogoApi import FakePogoApi
from .pgoapiwrapper import PGoApiWrapper


log = logging.getLogger(__name__)


class AccountManager(object):
    def __init__(self, args, db_queue, wh_queue, high_level=30):

        self.args = args
        self.dbq = db_queue
        self.whq = wh_queue
        self.key_scheduler = None
        self.high_level = high_level
        self.instance_id = args.instance_id
        self.accounts = {
             'scan': OrderedDict(),
             'hlvl': OrderedDict(),
             'active_scan': OrderedDict(),
             'active_hlvl': OrderedDict(),
             'failed': deque(),
             'captcha': deque()
        }

        self.accounts_lock = Lock()

        self.release_instance()
        self.account_keeper(notice=True)

        # Start account manager thread.
        log.info('Starting account manager thread...')
        self.manager = Thread(target=self.run_manager,
                              name='account-manager')
        self.manager.daemon = True
        self.manager.start()

    def run_manager(self):
        self.thread_id = 0
        cycle = 0
        time.sleep(60)
        while True:
            self.manager_sleep = 15
            cycle += 1

            # Run once every 15 seconds.
            if self.args.captcha_solving:
                self.captcha_manager()

            # Run once every 60 seconds.
            if cycle % 4 == 0:
                self.account_keeper(notice=(cycle % 40 == 0))
                self.account_recycler()

            # Run once every 10 min.
            if cycle % 40 != 0:
                self.account_monitor()
                cycle = 0

            time.sleep(self.manager_sleep)

    def captcha_manager(self):
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
                    target=self.captcha_solver,
                    name='captcha-solver-{}'.format(self.thread_id),
                    args=(hash_key, tokens[i]))
                t.daemon = True
                t.start()

                self.thread_id += 1
                if self.thread_id > 999:
                    self.thread_id = 0
                # Wait a bit before launching next thread.
                time.sleep(1)

            # Adjust captcha-manager sleep timer.
            self.manager_sleep -= 1 * solvers

            # Hybrid mode - after waiting send to automatic captcha solver.
            if self.args.captcha_key and self.args.manual_captcha_timeout > 0:
                tokens_remaining = tokens_needed - tokens_available
                # Safety guard, don't grab too much work.
                tokens_remaining = min(tokens_remaining, 5)
                for i in range(0, tokens_remaining):
                    account = self.accounts['captcha'][0][1]
                    hold_time = (datetime.utcnow() -
                                 account['last_scan']).total_seconds()
                    if hold_time > self.args.manual_captcha_timeout:
                        log.debug('Account %s waited %ds for captcha token ' +
                                  'and reached the %ds timeout.',
                                  account['username'], hold_time,
                                  self.args.manual_captcha_timeout)
                        hash_key = self.key_scheduler.next()

                        t = Thread(
                            target=self.captcha_solver,
                            name='captcha-solver-{}'.format(self.thread_id),
                            args=(hash_key, tokens[i]))
                        t.daemon = True
                        t.start()

                        self.thread_id += 1
                        if self.thread_id > 999:
                            self.thread_id = 0

                        # Wait a little bit before launching next thread.
                        time.sleep(1)
                    else:
                        break

    def captcha_solver(self, hash_key, token):
        status, account, captcha_url = self.accounts['captcha'].popleft()
        if status['username'] != account['username']:
            # Search worker has moved on, don't use its status.
            status = {
                'message': '',
                'captcha': 1,
            }
        status['message'] = 'Waking up account {} to solve captcha.'.format(
                            account['username'])
        log.info(status['message'])

        if self.args.mock != '':
            api = FakePogoApi(self.args.mock)
        else:
            api = PGoApiWrapper(PGoApi())

        if hash_key:
            log.debug('Using hash key %s to solve this captcha.', hash_key)
            api.activate_hash_server(hash_key)

        proxy_url = False
        if self.args.proxy:
            # Try to fetch a new proxy.
            proxy_num, proxy_url = get_new_proxy(self.args)

            if proxy_url:
                log.debug('Using proxy %s', proxy_url)
                api.set_proxy({'http': proxy_url, 'https': proxy_url})

        location = (account['latitude'], account['longitude'])
        altitude = get_altitude(self.args, location)
        location = (location[0], location[1], altitude)

        if self.args.jitter:
            # Jitter location before uncaptcha attempt.
            location = jitter_location(location)

        api.set_position(*location)
        check_login(self.args, account, api, proxy_url)

        if not token:
            token = token_request(self.args, status, captcha_url)

        req = api.create_request()
        req.verify_challenge(token=token)
        response = req.call(False)
        success = response['responses']['VERIFY_CHALLENGE'].success

        if success:
            status['message'] = (
                "Account {} successfully uncaptcha'd, returning to " +
                'active duty.').format(account['username'])
            log.info(status['message'])

            # Update account information in database.
            account['captcha'] = False
            self.dbq.put((Account, {0: Account.db_format(account)}))

            with self.accounts_lock:
                # Return account to the respective account pool.
                if account['level'] < self.high_level:
                    self.accounts['scan'][account['username']] = account
                else:
                    self.accounts['hlvl'][account['username']] = account
        else:
            status['message'] = (
                'Account {} failed verifyChallenge, putting back ' +
                'in captcha queue.').format(account['username'])
            log.warning(status['message'])
            self.accounts['captcha'].append((status, account, captcha_url))

        if 'captcha' in self.args.wh_types:
            hold_time = (datetime.utcnow() -
                         account['last_scan']).total_seconds()
            wh_message = {
                'status_name': self.args.status_name,
                'mode': 'manual' if token else '2captcha',
                'account': account['username'],
                'captcha': status['captcha'],
                'time': int(hold_time),
                'status': 'success' if success else 'failure'
            }
            self.whq.put(('captcha', wh_message))

        # Let things settle down a bit.
        time.sleep(1)

    def account_keeper(self, notice=False):
        # Check for missing scanning accounts.
        scan_count = (len(self.accounts['scan']) +
                      len(self.accounts['active_scan']))
        scan_missing = self.args.workers - scan_count
        scan_fetched = self.replenish_accounts(scan_missing, hlvl=False)
        if notice and scan_fetched < scan_missing:
            log.error('Insufficient scanner accounts in the database.')

        # Check for missing high-level accounts.
        hlvl_count = (len(self.accounts['hlvl']) +
                      len(self.accounts['active_hlvl']))
        hlvl_missing = self.args.hlvl_workers - hlvl_count
        hlvl_fetched = self.replenish_accounts(hlvl_missing, hlvl=True)
        if notice and hlvl_fetched < hlvl_missing:
            log.error('Insufficient high-level accounts in the database.')

    def account_recycler(self):
        now = datetime.utcnow()
        failed_count = len(self.accounts['failed'])
        log.debug('Account recycler running. Checking status of %d accounts.',
                  failed_count)

        # Search through failed account pool for recyclable accounts.
        while failed_count > 0:
            account, reason, notified = self.accounts['failed'].popleft()
            failed_count -= 1

            rest_interval = self.args.account_rest_interval

            if 'exception' in reason:
                rest_interval = rest_interval * 0.1
            elif 'banned' in reason:
                rest_interval = rest_interval * 10

            hold_time = (account['last_modified'] +
                         timedelta(seconds=rest_interval))

            if now >= hold_time:
                log.info('Account %s returning to active duty.',
                         account['username'])
                # Update account information in database.
                account['fail'] = False
                self.dbq.put((Account, {0: Account.db_format(account)}))

                with self.accounts_lock:
                    # Return account to the respective account pool.
                    if account['level'] < self.high_level:
                        self.accounts['scan'][account['username']] = account
                    else:
                        self.accounts['hlvl'][account['username']] = account
            else:
                if not notified:
                    time = (hold_time - now).total_seconds()
                    log.info('Account %s needs to stop (%s) for %.0f minutes.',
                             account['username'], reason, time/60)
                    notified = True
                self.accounts['failed'].append((account, reason, notified))

    def account_monitor(self):
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

    # Release accounts that may have been working for this instance.
    def release_instance(self):
        query = (Account
                 .update(allocated=False, fail=False)
                 .where(Account.instance_id == self.instance_id))
        rows = query.execute()
        log.debug('Released %d accounts previously used by this instance.',
                  rows)

    # Load accounts from the database.
    def load_accounts(self, count, reuse=False, hlvl=False):
        conditions = ((Account.allocated == 0) &
                      (Account.fail == 0) &
                      (Account.banned == 0))
        if reuse:
            conditions &= (Account.instance_id == self.instance_id)
        else:
            conditions &= (Account.instance_id.is_null() |
                           (Account.instance_id != self.instance_id))
        if hlvl:
            conditions &= (Account.level >= self.high_level)
        elif not self.args.hlvl_scan:
            conditions &= (Account.level < self.high_level)

        query = (Account
                 .select()
                 .where(conditions)
                 .order_by(Account.level.desc(), Account.last_modified.desc())
                 .limit(count)
                 .dicts())

        accounts = {}
        if hlvl:
            for dba in query:
                accounts[dba['username']] = dba
            log.debug('Loaded %d high level accounts.', len(query))
        else:
            for dba in query:
                accounts[dba['username']] = dba
            log.debug('Loaded %d accounts.', len(query))

        return accounts

    # Flag accounts that are going to be used by this instance.
    def allocate_accounts(self, accounts):
        step = 250

        if len(accounts) > 0:
            usernames = accounts.keys()
            rows = 0
            for idx in range(0, len(usernames), step):
                query = (Account
                         .update(allocated=True,
                                 instance_id=self.instance_id)
                         .where((Account.username <<
                                 usernames[idx:idx+step])))

                rows += query.execute()
            unallocated = len(usernames) - rows
            if unallocated > 0:
                log.error('Unable to allocate %d accounts.', unallocated)
                return False

        return True

    # Load and allocate accounts from the database.
    # TODO: remove try .. except
    def fetch_accounts(self, count, reuse, hlvl):
        accounts = {}
        try:
            with Account.database().atomic():
                accounts = self.load_accounts(count, reuse, hlvl)
                if not self.allocate_accounts(accounts):
                    return 0
        except Exception as e:
            log.exception(e)

        # Populate respective account pool.
        if hlvl:
            for username, account in accounts.iteritems():
                account['allocated'] = True
                account['instance_id'] = self.instance_id
                self.accounts['hlvl'][username] = account
        else:
            for username, account in accounts.iteritems():
                account['allocated'] = True
                account['instance_id'] = self.instance_id
                self.accounts['scan'][username] = account
        return len(accounts)

    def replenish_accounts(self, count, hlvl=False):
        if hlvl:
            log.debug('Fetching %d high-level accounts.', count)
        else:
            log.debug('Fetching %d scanner accounts.', count)
        fetch_count = 0
        with self.accounts_lock:
            if count > 0:
                fetch_count = self.fetch_accounts(
                    count, reuse=True, hlvl=hlvl)
                count -= fetch_count
            if count > 0:
                fetch_count += self.fetch_accounts(
                    count, reuse=False, hlvl=hlvl)

        return fetch_count

    # Release an account back to the pool after it was used.
    def release_account(self, account):
        # Update account information in database.
        username = account['username']
        self.dbq.put((Account, {0: Account.db_format(account)}))

        with self.accounts_lock:
            if self.accounts['active_hlvl'].pop(username, None):
                self.accounts['hlvl'][username] = account
            elif self.accounts['active_scan'].pop(username, None):
                self.accounts['scan'][username] = account
            else:
                log.error('Unable to find account %s in account pool.',
                          username)

    # Get next account that is ready to be used for scanning.
    def get_account(self, location=None, hlvl=False):
        if hlvl:
            accounts = self.accounts['hlvl']
            accounts_active = self.accounts['active_hlvl']
            speed_limit = self.args.hlvl_kph
        else:
            accounts = self.accounts['scan']
            accounts_active = self.accounts['active_scan']
            speed_limit = self.args.kph

        picked_account = None
        with self.accounts_lock:
            now = datetime.utcnow()
            picked_username = None
            # Loop through available accounts.
            # Reversed account iteration to maximize reusage.
            for username in reversed(accounts.keys()):
                account = accounts[username]
                # Check if we're below speed limit for account.
                if location and account['last_scan']:
                    time_passed = (now - account['last_scan']).total_seconds()
                    old_location = (account['latitude'], account['longitude'])

                    meters = distance(old_location, location)
                    cooldown_time_sec = meters / speed_limit * 3.6

                    # Not enough time has passed for this one.
                    sleep_time = cooldown_time_sec - time_passed
                    if sleep_time > 0:
                        continue

                # We've found an account that's available to scan.
                picked_username = username
                break

            picked_account = accounts.pop(picked_username, None)
            # Put account in circulation.
            if picked_account:
                accounts_active[picked_username] = picked_account

        return picked_account

    # Update account information in the database.
    def update_account(self, account):
        self.dbq.put((Account, {0: Account.db_format(account)}))

    # Remove account from rotation.
    def remove_account(self, account):
        if self.accounts['active_hlvl'].pop(account['username'], None):
            return True

        if self.accounts['active_scan'].pop(account['username'], None):
            return True

        return False

    def uncaptcha_account(self, account, status, api, captcha_url):
        username = account['username']

        if not self.args.captcha_solving:
            # Update account information in database.
            account['captcha'] = True
            account['fail'] = True
            self.dbq.put((Account, {0: Account.db_format(account)}))
            # Remove account from rotation.
            if not self.remove_account(username):
                log.error('Account %s was not active.', username)
                return False

            self.accounts['failed'].append((account, 'captcha'))
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
            return False

        if self.args.captcha_key and self.args.manual_captcha_timeout == 0:
            if self.automatic_captcha_solve(account, status, api, captcha_url):
                # Solved the captcha on the spot, no fuzz.
                return True

            # Update account information in database.
            account['captcha'] = True
            account['fail'] = True
            self.dbq.put((Account, {0: Account.db_format(account)}))

            # Remove account from rotation.
            if not self.remove_account(username):
                log.error('Account %s was not active.', username)
                return False

            self.accounts['failed'].append((account, 'captcha fail'))
            status['message'] = (
                'Account {} has encountered a captcha. ' +
                'Failed to uncaptcha, putting account away.').format(username)
            log.warning(status['message'])

            return False
        else:
            # Update account information in database.
            account['captcha'] = True
            self.dbq.put((Account, {0: Account.db_format(account)}))

            # Remove account from rotation.
            if not self.remove_account(username):
                log.error('Account %s was not active.', username)
                return False

            self.accounts['captcha'].append((account, status, captcha_url))
            status['message'] = (
                'Account {} has encountered a captcha. ' +
                'Waiting for token.').format(username)
            log.warning(status['message'])

            if 'captcha' in self.args.wh_types:
                wh_message = {
                    'status_name': self.args.status_name,
                    'status': 'encounter',
                    'mode': 'manual',
                    'account': username,
                    'captcha': status['captcha'],
                    'time': self.args.manual_captcha_timeout
                }
                self.whq.put(('captcha', wh_message))

            return False

    # Returns true if captcha was succesfully solved.
    def automatic_captcha_solve(self, account, status, api, captcha_url):
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
                    'Account {} failed to verify the captcha, putting away ' +
                    'account for now.').format(account['username'])
            log.info(status['message'])
            if 'captcha' in self.args.wh_types:
                wh_message['status'] = 'success' if success else 'failure'
                wh_message['time'] = time_elapsed
                self.whq.put(('captcha', wh_message))

            return success

    def failed_account(self, account, reason):
        # Update account information in database.
        username = account['username']
        account['fail'] = True
        self.dbq.put((Account, {0: Account.db_format(account)}))

        # Remove account from rotation.
        if not self.remove_account(account):
            log.error('Account %s not found in account pool.', username)
            return False

        if account['banned']:
            reason = 'banned'
        self.accounts['failed'].append((account, reason, False))


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
