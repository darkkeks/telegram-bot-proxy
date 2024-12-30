from dataclasses import dataclass
from telethon import TelegramClient, events
from telethon.tl.types import PeerUser, User, Message, MessageEntityMentionName
from typing import Optional
import logging
import os
import re
import time
import typing


logging.basicConfig(level=logging.INFO)


api_id = int(os.environ['TELEGRAM_API_ID'])
api_hash = os.environ['TELEGRAM_API_HASH']
bot_token = os.environ['TELEGRAM_BOT_TOKEN']


user_client = TelegramClient('user', api_id, api_hash)
bot_client = TelegramClient('bot', api_id, api_hash)


@dataclass
class ProxyRule:
    chat_id: int
    sandbox_chat_id: int
    media_share_chat_id: int


RULES = [
    ProxyRule(
        chat_id=int(os.environ['PROXY_CHAT_ID']),
        sandbox_chat_id=int(os.environ['PROXY_SANDBOX_CHAT_ID']),
        media_share_chat_id=int(os.environ['PROXY_MEDIA_SHARE_CHAT_ID']),
    ),
]


@dataclass
class RecentMessage:
    chat_id: int
    message_id: int
    user_id: int
    user_first_name: Optional[str]
    sandbox_chat_id: int
    sandbox_message_id: int
    timestamp_ms: int


NOT_RECENT_ANYMORE_MS = 5 * 60 * 1000
RECENT_MESSAGES: list[RecentMessage] = []


def cleanup_recent_messages():
    global RECENT_MESSAGES
    RECENT_MESSAGES = [
        rm for rm in RECENT_MESSAGES
        if int(1000 * time.time()) - rm.timestamp_ms < NOT_RECENT_ANYMORE_MS
    ]


def is_tiktoker_message(message: Message) -> bool:
    text = message.message
    if not text:
        return False
    domains = [
        'tiktok.com',
        'vm.tiktok.com',
        'tiktokcdn.com',
        'spotify.com',
        'youtube.com/shorts',
        'instagram.com/reels',
    ]
    return any(domain in text for domain in domains)


def try_patch_name(message) -> Message:
    logging.info(f'Trying to patch {message.stringify()}')

    last_message = None
    for rm in RECENT_MESSAGES:
        if rm.sandbox_chat_id == message.chat_id:
            if last_message is None or rm.timestamp_ms > last_message.timestamp_ms:
                last_message = rm

    timestamp_current = int(1000 * time.time())
    if not last_message or timestamp_current - last_message.timestamp_ms > NOT_RECENT_ANYMORE_MS or last_message.user_first_name is None:
        logging.info(f'Bad last message: {last_message}')
        return message

    text = message.message
    match = re.search(r'^Downloaded: (.*)$', text, re.MULTILINE)
    if not match:
        logging.info(f'Match not found: {message.message}, {match}')
        return message

    offset, length = match.start(1), len(match.group(1))

    if not message.entities:
        logging.info(f'No entities :(')
        return message

    message.message = text[:offset] + last_message.user_first_name + text[offset+length:]

    for entity in message.entities:
        if isinstance(entity, MessageEntityMentionName) and entity.offset == offset or entity.length == length:
            entity.length = len(last_message.user_first_name)
            entity.user_id = last_message.user_id
            continue

        if entity.offset > offset:
            entity.offset -= len(match.group(1))
            entity.offset += len(last_message.user_first_name)

    logging.info(f'Patched! {message.stringify()}')

    return message


@bot_client.on(events.NewMessage(incoming=True))
async def bot_message_handler(event: events.NewMessage.Event):
    cleanup_recent_messages()
    for rule in RULES:
        if event.chat_id == rule.chat_id:
            logging.info(f'Received message from source chat {rule.chat_id}, forwarding to sandbox chat {rule.sandbox_chat_id}')

            message = event.message
            if not is_tiktoker_message(message):
                logging.info(f'Message not matched, id={message.id}')
                continue

            peer = message.from_id or message.peer_id
            if not isinstance(peer, PeerUser):
                logging.info(f'Message is not from user, id={message.id}')
                continue

            user = await user_client.get_entity(peer)
            user = typing.cast(User, user)
            logging.info(f'Fetched user: {user.stringify()}')

            sandbox_message = await user_client.send_message(rule.sandbox_chat_id, message)

            recent_message = RecentMessage(
                chat_id=message.chat_id,
                message_id=message.id,
                user_id=peer.user_id,
                user_first_name=user.first_name,
                sandbox_chat_id=rule.sandbox_chat_id,
                sandbox_message_id=sandbox_message.id,
                timestamp_ms=int(1000 * time.time()),
            )
            logging.info(f'Recent message: {recent_message}')
            RECENT_MESSAGES.append(recent_message)

        if event.chat_id == rule.media_share_chat_id:
            logging.info(f'Received message from media share chat {rule.media_share_chat_id}, forwarding to source chat {rule.chat_id}')

            message = event.message
            await message.forward_to(rule.chat_id, drop_author=True)


@user_client.on(events.NewMessage(incoming=True))
async def user_message_handler(event: events.NewMessage.Event):
    cleanup_recent_messages()
    for rule in RULES:
        if event.chat_id == rule.sandbox_chat_id:
            logging.info(f'Received message from sandbox chat {rule.sandbox_chat_id}, forwarding to source chat {rule.chat_id}')

            message = event.message

            message = try_patch_name(message)

            if not message.media:
                await bot_client.send_message(rule.chat_id, message)
            else:
                await user_client.send_message(rule.media_share_chat_id, message)


@user_client.on(events.MessageDeleted())
async def user_message_deleted(event: events.MessageDeleted.Event):
    for rule in RULES:
        if event.chat_id == rule.sandbox_chat_id:
            recent_message = None
            for rm in RECENT_MESSAGES:
                if rm.sandbox_message_id == event.deleted_id:
                    recent_message = rm

            if not recent_message:
                continue

            logging.info(f'Deleting original message: {recent_message}')
            await bot_client.delete_messages(recent_message.chat_id, recent_message.message_id)


if __name__ == '__main__':
    bot_client.start(bot_token=bot_token)
    user_client.start()
    user_client.run_until_disconnected()
