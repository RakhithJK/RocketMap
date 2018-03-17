#!/usr/bin/python
# -*- coding: utf-8 -*-

import logging
import requests
import urllib
from datetime import datetime, timedelta

from flask import redirect
from requests.exceptions import HTTPError

log = logging.getLogger(__name__)


class DiscordAPI():
    ENDPOINT = 'https://discordapp.com/api/v6'

    def __init__(self, args):
        self.client_id = args.user_auth_client_id
        self.client_secret = args.user_auth_client_secret
        self.bot_token = args.user_auth_bot_token

        self.hostname = args.host
        if args.user_auth_hostname:
            self.hostname = args.user_auth_hostname

        self.redirect_uri = '{}/auth_callback'.format(self.hostname)

        self.guild_required = args.user_auth_guild_required
        self.guild_invite_link = args.user_auth_guild_invite
        self.role_required = args.user_auth_role_required
        self.role_invite_link = args.user_auth_role_invite
        self.bot_token = args.user_auth_bot_token

        self.guild_roles = self.get_guild_role_names()

    def post_request(self, uri, data, headers):
        url = '{}/{}'.format(self.ENDPOINT, uri)
        r = requests.post(url, data, headers)
        try:
            r.raise_for_status()
            return r.json()
        except HTTPError:
            log.error('Failed POST request to Discord API at %s: %s - %s.',
                      url, r.status_code, r.text)

        return None

    def get_request(self, uri, headers, params=None):
        url = '{}/{}'.format(self.ENDPOINT, uri)
        r = requests.get(url, params, headers=headers)
        try:
            r.raise_for_status()
            return r.json()
        except HTTPError:
            log.error('Failed GET request to Discord API at %s: %s - %s.',
                      url, r.status_code, r.text)

        return None

    # https://discordapp.com/developers/docs/topics/oauth2#authorization-code-grant-access-token-response
    def exchange_code(self, code):
        uri = '/oauth2/token'
        data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': self.redirect_uri
        }
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }

        return self.post_request(uri, data, headers)

    def refresh_token(self, refresh_token):
        uri = '/oauth2/token'
        data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'grant_type': 'refresh_token',
            'code': refresh_token,
            'redirect_uri': self.redirect_uri
        }
        headers = {
          'Content-Type': 'application/x-www-form-urlencoded'
        }

        return self.post_request(uri, data, headers)

    def validate_auth(self, session, response):
        expires_in = response.get('expires_in', 0) - 3600
        if expires_in <= 0:
            log.error('Invalid OAuth response from Discord API.')
            return False

        response['expires'] = (datetime.utcnow() +
                               timedelta(seconds=expires_in))
        session['user_auth'] = response
        return True

    def redirect_to_auth(self):
        redirect_uri = urllib.quote(self.redirect_uri)
        url = ('{}/oauth2/authorize?response_type=code&client_id={}&'
               'redirect_uri={}&scope=identify%20guilds').format(
                   self.ENDPOINT, self.client_id, redirect_uri)
        return redirect(url)

    # https://discordapp.com/developers/docs/topics/oauth2#authorization-code-grant
    def check_auth(self, session):
        user_auth = session.get('user_auth')
        if not user_auth:
            return self.redirect_to_auth()

        if user_auth['expires'] < datetime.utcnow():
            response = self.refresh_token(user_auth['refresh_token'])
            if not response or not self.validate_auth(session, response):
                return self.redirect_to_auth()

        auth_token = user_auth['access_token']

        if not self.guild_required:
            return None

        guild_ids = user_auth.get('guilds', [])
        if not guild_ids:
            user_guilds = self.get_user_guilds(auth_token)
            if not user_guilds:
                log.error('Unable to retrieve user guilds from Discord API.')
                return self.redirect_to_auth()
            guild_ids = [x['id'] for x in user_guilds]
            session['user_auth']['guilds'] = guild_ids

        if self.guild_required not in guild_ids:
            return redirect(self.guild_invite_link)

        if not self.role_required:
            return None

        user_id = user_auth.get('user_id', None)
        if not user_id:
            user_data = self.get_user(auth_token)
            if not user_data:
                log.error('Unable to retrieve user data from Discord API.')
                return self.redirect_to_auth()
            user_id = user_data['id']
            session['user_auth']['user_id'] = user_id

        roles = user_auth.get('roles', [])
        if not roles:
            guild_member = self.get_guild_member(self.guild_required, user_id)
            if not guild_member:
                log.error('Unable to retrieve user roles from Discord API.')
                return self.redirect_to_auth()

            role_ids = guild_member.get('roles', [])
            role_names = []
            for role_id in role_ids:
                role_name = self.guild_roles.get(role_id, None)
                if role_name:
                    role_names.append(role_name)

            session['user_auth']['roles'] = role_names

        for role_required in self.role_required:
            if role_required in roles:
                return None

        return redirect(self.role_invite_link)

    # https://discordapp.com/developers/docs/resources/user#get-current-user-guilds
    def get_user_guilds(self, auth_token):
        endpoint = 'users/@me/guilds'
        headers = {
          'Authorization': 'Bearer ' + auth_token
        }

        return self.get_request(endpoint, headers)

    # https://discordapp.com/developers/docs/resources/user#get-current-user
    # https://discordapp.com/developers/docs/resources/user#user-object
    def get_user(self, auth_token):
        endpoint = 'users/@me'
        headers = {
          'Authorization': 'Bearer ' + auth_token
        }

        return self.get_request(endpoint, headers)

    # https://discordapp.com/developers/docs/resources/guild#get-guild-member
    # https://discordapp.com/developers/docs/resources/guild#guild-member-object
    def get_guild_member(self, guild_id, user_id):
        endpoint = 'guilds/{}/members/{}'.format(guild_id, user_id)
        headers = {
            'Authorization': 'Bot ' + self.bot_token
        }

        return self.get_request(endpoint, headers)

    # https://discordapp.com/developers/docs/resources/guild#get-guild-roles
    def get_guild_roles(self, guild_id):
        endpoint = 'guilds/{}/roles'.format(guild_id)
        headers = {
            'Authorization': 'Bot ' + self.bot_token
        }

        return self.get_request(endpoint, headers)

    # Translate role IDs to names.
    # https://discordapp.com/developers/docs/topics/permissions#role-object
    def get_guild_role_names(self):
        roles = {}
        guild_roles = self.get_guild_roles(self.guild_required)
        if not guild_roles:
            log.error('Unable to retrieve guild roles from Discord API.')
            return False

        for role in guild_roles:
            roles[role['id']] = role['name']

        return roles
