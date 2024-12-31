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

    def has_chat_id(self, chat_id: int):
        return chat_id in (self.chat_id, self.sandbox_chat_id, self.media_share_chat_id)


RULES = [
    ProxyRule(
        chat_id=int(os.environ['PROXY_CHAT_ID']),
        sandbox_chat_id=int(os.environ['PROXY_SANDBOX_CHAT_ID']),
        media_share_chat_id=int(os.environ['PROXY_MEDIA_SHARE_CHAT_ID']),
    ),
]

def select_rule(chat_id: int) -> Optional[ProxyRule]:
    for rule in RULES:
        if rule.has_chat_id(chat_id):
            return rule
    return None


def now():
    return int(1000 * time.time())


@dataclass
class AuthorMeta:
    user_id: int
    first_name: str

    @classmethod
    def from_user(cls, user: User) -> Optional['AuthorMeta']:
        if not user.first_name:
            return None
        return cls(user.id, user.first_name)


@dataclass(frozen=True)
class MessageInstanceId:
    chat_id: int
    message_id: int


@dataclass
class MessageChain:
    author: Optional[AuthorMeta] = None

    source: Optional[MessageInstanceId] = None
    target: Optional[MessageInstanceId] = None
    shared: Optional[MessageInstanceId] = None

    timestamp_ms: int = now()

    def is_expired(self, threshold_ms=10 * 60 * 1000):
        return self.timestamp_ms + threshold_ms < now()


CHAINS: list[MessageChain] = []


def select_chain(source: Optional[MessageInstanceId] = None,
                 target: Optional[MessageInstanceId] = None,
                 shared: Optional[MessageInstanceId] = None) -> Optional[MessageChain]:
    for chain in CHAINS:
        if source is not None and chain.source != source:
            continue
        if target is not None and chain.target != target:
            continue
        if shared is not None and chain.shared != shared:
            continue
        return chain
    return None


def cleanup_chains():
    global CHAINS

    new_chains = []
    shared = {}
    for chain in CHAINS:
        if chain.is_expired():
            continue

        # merge chains that have the same shared message.
        previous = shared.get(chain.shared, None)
        if previous is not None:
            if chain.target is not None and previous.target is None:
                previous.target = chain.target
            if chain.source is not None and previous.source is None:
                previous.source = chain.source
            if chain.author is not None and previous.author is None:
                previous.author = chain.author
            continue

        shared[chain.shared] = chain
        new_chains.append(chain)

    CHAINS = new_chains
    logging.info(f'Current chains: {CHAINS}')


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
    message_id = MessageInstanceId(message.chat_id, message.id)
    logging.info(f'Patching {message_id}')

    chain = None
    for c in CHAINS:
        if not c.is_expired() and c.target and c.target.chat_id == message_id.chat_id:
            if chain is None or c.timestamp_ms > chain.timestamp_ms:
                chain = c

    if not chain or chain.author is None:
        logging.info(f'Cannot patch, bad chain: {chain}')
        return message

    text = message.message
    match = re.search(r'^Downloaded: (.*)$', text, re.MULTILINE)
    if not match:
        logging.info(f'Cannot patch, message not matched')
        return message

    if not message.entities:
        logging.info(f'Cannot patch, message has no entities')
        return message

    offset, length = match.start(1), len(match.group(1))
    message.message = text[:offset] + chain.author.first_name + text[offset+length:]

    for entity in message.entities:
        if isinstance(entity, MessageEntityMentionName) and entity.offset == offset and entity.length == length:
            entity.length = len(chain.author.first_name)
            entity.user_id = chain.author.user_id
            continue

        if entity.offset > offset:
            entity.offset -= len(match.group(1))
            entity.offset += len(chain.author.first_name)

    return message


async def fetch_user(message: Message) -> Optional[User]:
    peer = message.from_id or message.peer_id
    if not isinstance(peer, PeerUser):
        return None

    user = await user_client.get_entity(peer)
    return typing.cast(User, user)


@bot_client.on(events.NewMessage(incoming=True))
async def bot_message_handler(event: events.NewMessage.Event):
    cleanup_chains()

    if not event.chat_id:
        return
    message_id = MessageInstanceId(event.chat_id, event.message.id)

    rule = select_rule(message_id.chat_id)
    if not rule:
        return

    if event.chat_id == rule.chat_id:
        logging.info(f'Processing original message {message_id}')

        message = event.message
        if not is_tiktoker_message(message):
            logging.info(f'Skipping message id={message_id}, not matched by filter')
            return

        user = await fetch_user(message)
        if user is None:
            logging.info(f'Skipping message id={message_id}, not from user')
            return

        sandboxed = await user_client.send_message(rule.sandbox_chat_id, message)
        sandboxed_id = MessageInstanceId(rule.sandbox_chat_id, sandboxed.id)

        chain = MessageChain(
            author=AuthorMeta.from_user(user),
            source=message_id,
            target=sandboxed_id,
        )
        logging.info(f'New chain: {chain}')
        CHAINS.append(chain)

    if event.chat_id == rule.media_share_chat_id:
        logging.info(f'Processing media share message {message_id}')

        target = await event.message.forward_to(rule.chat_id, drop_author=True)
        target_id = MessageInstanceId(rule.chat_id, target.id)

        chain = select_chain(shared=message_id)
        if chain:
            chain.target = target_id
            logging.info(f'Updated chain: {chain}')
        else:
            # Previous chain may be missing if message was received before sender got confirmation.
            chain = MessageChain(
                shared=message_id,
                target=target_id,
            )
            logging.info(f'New chain: {chain}')
            CHAINS.append(chain)


@user_client.on(events.NewMessage(incoming=True))
async def user_message_handler(event: events.NewMessage.Event):
    cleanup_chains()

    if not event.chat_id:
        return
    message_id = MessageInstanceId(event.chat_id, event.message.id)

    rule = select_rule(event.chat_id)
    if not rule:
        return

    if event.chat_id == rule.sandbox_chat_id:
        logging.info(f'Processing sandbox message {message_id}')

        message = event.message
        message = try_patch_name(message)

        user = await fetch_user(message)
        if user is None:
            logging.info(f'Skipping message id={message_id}, not from user')
            return

        if message.media:
            shared = await user_client.send_message(rule.media_share_chat_id, message)
            shared_id = MessageInstanceId(rule.media_share_chat_id, shared.id)
            chain = MessageChain(
                author=AuthorMeta.from_user(user),
                source=message_id,
                shared=shared_id,
            )
        else:
            passed = await bot_client.send_message(rule.chat_id, message)
            passed_id = MessageInstanceId(rule.chat_id, passed.id)
            chain = MessageChain(
                author=AuthorMeta.from_user(user),
                source=message_id,
                target=passed_id,
            )

        logging.info(f'New chain: {chain}')
        CHAINS.append(chain)


@bot_client.on(events.MessageEdited())
async def bot_message_edited(event: events.MessageEdited.Event):
    cleanup_chains()

    if not event.chat_id:
        return
    message_id = MessageInstanceId(event.chat_id, event.message.id)

    chain = select_chain(shared=message_id)
    if not chain:
        logging.info(f'Skipping edited shared message {message_id}, no chain found')
        return

    message = event.message
    if not chain.target:
        logging.warning(f'Unexpected chain edit: {chain}')
        return

    await bot_client.edit_message(
        entity=chain.target.chat_id,
        message=chain.target.message_id,  # type: ignore
        text=message.message,
        file=message.media,  # type: ignore
        formatting_entities=message.entities,
    )


@user_client.on(events.MessageEdited())
async def user_message_edited(event: events.MessageEdited.Event):
    cleanup_chains()

    if not event.chat_id:
        return
    message_id = MessageInstanceId(event.chat_id, event.message.id)

    chain = select_chain(source=message_id)
    if not chain:
        logging.info(f'Skipping edited source message {message_id}, no chain found')
        return

    message = event.message
    message = try_patch_name(message)

    if message.media and not chain.shared:
        logging.warning(f'Skipping message edit because media was added, but the chain has not been shared: {chain}')
        return

    if chain.shared:
        await user_client.edit_message(
            entity=chain.shared.chat_id,
            message=chain.shared.message_id,  # type: ignore
            text=message.message,
            file=message.media,  # type: ignore
            formatting_entities=message.entities,
        )
    elif chain.target:
        await user_client.edit_message(
            entity=chain.target.chat_id,
            message=chain.target.message_id,  # type: ignore
            text=message.message,
            file=message.media,  # type: ignore
            formatting_entities=message.entities,
        )
    else:
        logging.warning(f'Unexpected chain edit: {chain}')


@user_client.on(events.MessageDeleted())
async def user_message_deleted(event: events.MessageDeleted.Event):
    cleanup_chains()

    if not event.chat_id or not event.deleted_id:
        return
    message_id = MessageInstanceId(event.chat_id, event.deleted_id)

    target_chain = select_chain(target=message_id)
    if target_chain:
        if not target_chain.source:
            logging.warning(f'Deleted chain is missing source: {target_chain.source}')
            return

        logging.info(f'Deleting source message: {target_chain}')
        await bot_client.delete_messages(target_chain.source.chat_id, target_chain.source.message_id)

    source_chain = select_chain(source=message_id)
    if source_chain:
        if not source_chain.target:
            logging.warning(f'Deleted chain is missing target: {source_chain.target}')
            return

        logging.info(f'Deleting target message: {source_chain}')
        await bot_client.delete_messages(source_chain.target.chat_id, source_chain.target.message_id)


if __name__ == '__main__':
    bot_client.start(bot_token=bot_token)
    user_client.start()
    user_client.run_until_disconnected()
